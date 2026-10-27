package engine

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// x86 listings are LLVM's Intel syntax; Ghidra's is Intel syntax too, in
// upper case and with its own spelling of memory operands and condition
// codes. normalizeX86 maps both to one form.

var x86Syntax = isaSyntax{
	comment:     "#",
	prefixes:    map[string]bool{"lock": true, "rep": true, "repe": true, "repne": true},
	normalize:   normalizeX86,
	divergences: x86Divergences,
}

// x86Conds maps Ghidra's condition-code spellings to LLVM's.
var x86Conds = map[string]string{
	"z": "e", "nz": "ne", "c": "b", "nc": "ae", "nae": "b", "nb": "ae",
	"na": "be", "nbe": "a", "nge": "l", "nl": "ge", "ng": "le", "nle": "g",
	"pe": "p", "po": "np",
}

// x86Aliases maps LLVM mnemonics to Ghidra's spelling of the same
// instruction.
var x86Aliases = map[string]string{
	"movabs": "mov", // mov r64, imm64
	"pushal": "pushad",
	"popal":  "popad",
}

// x87 operands: Ghidra sizes memory as float, double and extended and
// writes registers ST0..ST7; LLVM writes dword, qword and tbyte, and st,
// st(1)..st(7).
var (
	x87Sizes = strings.NewReplacer("floatptr", "dwordptr", "doubleptr", "qwordptr", "extendedptr", "tbyteptr")
	x87Reg   = regexp.MustCompile(`st\(([0-7])\)`)
	x87Top   = regexp.MustCompile(`(^|,)st(,|$)`)
)

var x86Shifts = map[string]bool{
	"shl": true, "sal": true, "shr": true, "sar": true, "rol": true, "ror": true, "rcl": true, "rcr": true,
}

var (
	x86Mem     = regexp.MustCompile(`\[[^\]]*\]`)
	x86Term    = regexp.MustCompile(`[+-]?[^+-]+`)
	x86Hex     = regexp.MustCompile(`\b0x[0-9a-f]+\b`)
	x86Address = regexp.MustCompile(`0x[0-9a-f]+`)
)

func normalizeX86(in objdumpInsn) (string, string) {
	m := strings.ToLower(in.mnemonic)
	// Ghidra writes prefixes as a suffix: "XADD.LOCK", "STOSQ.REP".
	if base, pre, ok := strings.Cut(m, "."); ok {
		m = pre + " " + base
	}
	words := strings.Fields(m)
	last := words[len(words)-1]
	for _, p := range []string{"j", "set", "cmov"} {
		if c, ok := x86Conds[strings.TrimPrefix(last, p)]; ok && strings.HasPrefix(last, p) {
			last = p + c
		}
	}
	if alias, ok := x86Aliases[last]; ok {
		last = alias
	}
	words[len(words)-1] = last
	m = strings.Join(words, " ")

	ops := strings.ToLower(in.operands)
	if i := strings.Index(ops, "<"); i >= 0 {
		ops = ops[:i] // branch target annotation
	}
	ops = strings.Join(strings.Fields(ops), "")
	ops = x87Sizes.Replace(ops)
	ops = x87Reg.ReplaceAllString(ops, "st$1")
	ops = x87Top.ReplaceAllString(x87Top.ReplaceAllString(ops, "${1}st0$2"), "${1}st0$2")
	// LLVM shows a rip-relative operand as [rip+disp] and its target in the
	// comment; Ghidra shows the target.
	if strings.Contains(ops, "[rip") {
		if a := x86Address.FindString(in.comment); a != "" {
			ops = x86Mem.ReplaceAllLiteralString(ops, "["+a+"]")
		}
	}
	ops = x86Mem.ReplaceAllStringFunc(ops, normalizeX86Mem)
	ops = x86Hex.ReplaceAllStringFunc(ops, func(h string) string {
		v, _ := strconv.ParseUint(h[2:], 16, 64)
		return strconv.FormatUint(v, 10)
	})
	ops = foldX86Negative(ops)
	// LLVM omits the count of the shift-by-one encoding.
	if x86Shifts[last] && !strings.Contains(ops, ",") {
		ops += ",1"
	}
	return m, ops
}

// normalizeX86Mem writes a memory operand as [base+index*scale+disp] with
// a decimal displacement, dropping a scale of 1 and a zero displacement.
func normalizeX86Mem(mem string) string {
	var regs []string
	var disp int64
	for _, term := range x86Term.FindAllString(mem[1:len(mem)-1], -1) {
		neg := strings.HasPrefix(term, "-")
		term = strings.TrimLeft(term, "+-")
		a, b, scaled := strings.Cut(term, "*")
		if !scaled {
			if v, ok := parseX86Number(term); ok {
				if neg {
					v = -v
				}
				disp += v
				continue
			}
			regs = append(regs, term)
			continue
		}
		if _, ok := parseX86Number(a); ok {
			a, b = b, a // LLVM writes scale*index
		}
		if s, _ := parseX86Number(b); s == 1 {
			regs = append(regs, a)
		} else {
			regs = append(regs, fmt.Sprintf("%s*%d", a, s))
		}
	}
	s := strings.Join(regs, "+")
	switch {
	case disp > 0 && s != "":
		s += fmt.Sprintf("+%d", disp)
	case disp < 0:
		s += fmt.Sprintf("%d", disp)
	case disp > 0 || s == "":
		s = fmt.Sprint(disp)
	}
	return "[" + s + "]"
}

func parseX86Number(s string) (int64, bool) {
	if strings.HasPrefix(s, "0x") {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		return int64(v), err == nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return int64(v), err == nil
}

var x86Negative = regexp.MustCompile(`(^|,)-([0-9]+)`)

// foldX86Negative writes negative immediates as their 32-bit two's
// complement, the form both tools agree on for most operand sizes.
func foldX86Negative(ops string) string {
	return x86Negative.ReplaceAllStringFunc(ops, func(s string) string {
		lead := ""
		if strings.HasPrefix(s, ",") {
			lead, s = ",", s[1:]
		}
		v, _ := strconv.ParseInt(s, 10, 64)
		return lead + strconv.FormatUint(uint64(uint32(v)), 10)
	})
}

var (
	x86PtrSize   = regexp.MustCompile(`\b(byte|word|dword|qword) ptr `)
	x86StringOps = regexp.MustCompile(`^(rep |repe |repne )?(movs|stos|lods|scas|cmps|ins|outs)[bwdq]$`)
)

// x86Opcode returns the first opcode byte after any legacy and REX
// prefixes.
func x86Opcode(b []byte) byte {
	for _, c := range b {
		switch {
		case c == 0x66 || c == 0x67 || c == 0xf0 || c == 0xf2 || c == 0xf3,
			c == 0x26 || c == 0x2e || c == 0x36 || c == 0x3e || c == 0x64 || c == 0x65,
			c&0xf0 == 0x40:
			continue
		}
		return c
	}
	return 0
}

var x86Divergences = []divergence{
	{
		name:   "x86-moffs-no-size",
		reason: "ia.sinc prints the moffs operand of mov a0-a3 as a bare [address] without a size",
		match: func(got, want objdumpInsn, _ bool) bool {
			if op := x86Opcode(got.bytes); op < 0xa0 || op > 0xa3 {
				return false
			}
			gm, gops := normalizeX86(got)
			want.operands = x86PtrSize.ReplaceAllString(want.operands, "")
			wm, wops := normalizeX86(want)
			return gm == wm && gops == wops
		},
	},
	{
		name:   "x86-string-operands",
		reason: "ia.sinc prints string instructions with their pointer registers (MOVSB.REP RDI,RSI) where LLVM prints the implied memory operands",
		match: func(got, want objdumpInsn, _ bool) bool {
			gm, _ := normalizeX86(got)
			wm, _ := normalizeX86(want)
			return gm == wm && x86StringOps.MatchString(gm)
		},
	},
	{
		name:   "x86-hint-nop-shadows-prefetch",
		reason: "the high5=3 hint NOP in ia.sinc precedes PREFETCHh in the compiled decision tree, so 0f 18 /1-/3 prints as NOP",
		match: func(got, want objdumpInsn, _ bool) bool {
			return strings.EqualFold(got.mnemonic, "nop") && strings.HasPrefix(want.mnemonic, "prefetch") &&
				len(got.bytes) >= 2 && bytes.Contains(got.bytes, []byte{0x0f, 0x18})
		},
	},
	{
		name:   "x86-repeated-opsize-prefix",
		reason: "ia.sinc toggles opsize with $xor for each 0x66 prefix, so an even number of them shows a dword operand where LLVM shows word",
		match: func(got, want objdumpInsn, _ bool) bool {
			n := 0
			for n < len(got.bytes) && got.bytes[n] == 0x66 {
				n++
			}
			return n >= 2 && n%2 == 0 && strings.EqualFold(got.mnemonic, want.mnemonic) &&
				strings.Contains(strings.ToLower(got.operands), "dword ptr") &&
				strings.Contains(want.operands, "word ptr") && !strings.Contains(want.operands, "dword ptr")
		},
	},
}
