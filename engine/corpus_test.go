package engine

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stohirov/decompile-anything/internal/loader"
	"github.com/stohirov/decompile-anything/internal/sleigh"
)

// The decoder harness: decode every object in the synthetic corpus and
// compare it, instruction by instruction, with the llvm-objdump listing
// committed next to it (see `make corpus`).
//
// Instruction boundaries must match exactly. Mnemonics and operands are
// compared after normalizing pure syntax (spacing, hex vs decimal, alias
// spellings). Where Ghidra's spec displays an instruction differently from
// LLVM for a known reason, the difference is counted under a named
// divergence instead of failing the test. Anything else fails.
//
// Set CORPUS_VERBOSE=1 with -v to log every divergence.

type objdumpInsn struct {
	addr     uint64
	length   int
	mnemonic string
	operands string
	comment  string // objdump's trailing annotation, such as an x86 rip-relative target
	bytes    []byte
}

var objdumpLine = regexp.MustCompile(`^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2,8} ?)+)\s*\t(\S+)(?:\t(.*))?$`)

func readObjdump(t *testing.T, path string, syn isaSyntax) map[uint64]objdumpInsn {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, err := parseObjdump(f, syn)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// parseObjdump parses a listing, splitting each line's operands from the
// comment after the syntax's marker. A prefix objdump prints on a line of
// its own (x86 "lock") is merged into the instruction it prefixes, and one
// printed in the mnemonic column ("rep\t\tmovsb") is joined with the
// mnemonic after it.
func parseObjdump(r io.Reader, syn isaSyntax) (map[uint64]objdumpInsn, error) {
	out := map[uint64]objdumpInsn{}
	var prefix *objdumpInsn
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		m := objdumpLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		var in objdumpInsn
		in.addr, _ = strconv.ParseUint(m[1], 16, 64)
		in.bytes, _ = hex.DecodeString(strings.ReplaceAll(m[2], " ", ""))
		in.length = len(in.bytes)
		in.mnemonic = m[3]
		in.operands, in.comment, _ = strings.Cut(m[4], syn.comment)
		if syn.prefixes[in.mnemonic] {
			if f := strings.Fields(in.operands); len(f) > 0 {
				in.mnemonic += " " + f[0]
				in.operands = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(in.operands), f[0]))
			}
		}
		if prefix != nil && prefix.addr+uint64(prefix.length) == in.addr {
			in.addr, in.length, in.mnemonic = prefix.addr, prefix.length+in.length, prefix.mnemonic+" "+in.mnemonic
			in.bytes = append(prefix.bytes, in.bytes...)
		}
		prefix = nil
		if syn.prefixes[in.mnemonic] && strings.TrimSpace(in.operands) == "" {
			prefix = &in
			continue
		}
		out[in.addr] = in
	}
	return out, sc.Err()
}

var armConds = []string{"eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"}

// condSynonyms folds condition codes with two names.
var condSynonyms = map[string]string{"cs": "hs", "cc": "lo"}

// condInfix matches Ghidra's ".cond" inside IT blocks, before an optional
// data type: "mov.eq", "vmov.gt.f32".
var condInfix = regexp.MustCompile(`\.(` + strings.Join(armConds, "|") + `)(\.|$)`)

// fusedCond lists base mnemonics LLVM writes with a fused condition suffix
// ("moveq", "blo") that the normalizer splits off.
var fusedCond = map[string]bool{
	"b": true, "bl": true, "bx": true, "mov": true, "cpy": true, "add": true, "sub": true,
	"ldr": true, "str": true, "cmp": true, "lsr": true, "lsl": true, "asr": true,
	"rsb": true, "sdiv": true, "udiv": true,
}

// vfpFusedCond matches LLVM's condition between a VFP mnemonic and its data
// type: "vmovgt.f32".
var vfpFusedCond = regexp.MustCompile(`^(v[a-z]+?)(` + strings.Join(armConds, "|") + `)(\..+)$`)

var vfpBases = map[string]bool{
	"vmov": true, "vadd": true, "vsub": true, "vmul": true, "vdiv": true, "vneg": true,
	"vabs": true, "vsqrt": true, "vcmp": true, "vcmpe": true, "vcvt": true, "vldr": true, "vstr": true,
}

// mnemonicAliases folds spellings of the same instruction, compared
// without condition code or width qualifier.
var mnemonicAliases = map[string]string{
	"cpy":      "mov",
	"ldmia":    "ldm",
	"stmia":    "stm",
	"vldr.64":  "vldr",
	"vstr.64":  "vstr",
	"vldr.32":  "vldr",
	"vstr.32":  "vstr",
	"vmov.s32": "vmov.32",
}

var shiftOperand = regexp.MustCompile(`^r\w+,r\w+,(lsl|lsr|asr|ror)`)

// normalize maps an instruction from either tool to a common form: lower
// case, no .w/.n width qualifier, conditions written once and in one
// place, aliases folded, and operands normalized (see normalizeOperands).
// Some aliases depend on the operands: LLVM prints push/pop for
// stmdb/ldmia on sp, a shift mnemonic for mov with a shifted register,
// add rd, pc as adr, and the full three-operand form of Thumb's 16-bit
// negate and multiply.
func normalize(mnemonic, operands string) (string, string) {
	m := strings.ToLower(mnemonic)
	trimWidth := func(s string) string { return strings.TrimSuffix(strings.TrimSuffix(s, ".w"), ".n") }
	m = trimWidth(m)
	cond := ""
	if loc := condInfix.FindStringSubmatchIndex(m); loc != nil {
		cond = m[loc[2]:loc[3]]
		m = trimWidth(m[:loc[0]] + m[loc[4]:])
		m = strings.TrimSuffix(m, ".")
	} else if loc := vfpFusedCond.FindStringSubmatch(m); loc != nil && vfpBases[loc[1]] {
		m, cond = loc[1]+loc[3], loc[2]
	} else {
		for _, c := range armConds {
			if b := strings.TrimSuffix(m, c); b != m && fusedCond[b] {
				m, cond = b, c
				break
			}
		}
	}
	if syn, ok := condSynonyms[cond]; ok {
		cond = syn
	}
	if alias, ok := mnemonicAliases[m]; ok {
		m = alias
	}

	ops := normalizeOperands(operands, floatBits(m))
	switch {
	case m == "stmdb" && strings.HasPrefix(ops, "sp!,"):
		m, ops = "push", strings.TrimPrefix(ops, "sp!,")
	case m == "ldm" && strings.HasPrefix(ops, "sp!,"):
		m, ops = "pop", strings.TrimPrefix(ops, "sp!,")
	case m == "mov" && shiftOperand.MatchString(ops):
		sh := shiftOperand.FindStringSubmatch(ops)[1]
		m, ops = sh, strings.Replace(ops, sh, "", 1)
	case (m == "add" || m == "sub") && strings.Contains(ops, ",pc,"):
		m, ops = "adr", firstOperand(ops) // the tools show the target differently
	case m == "adr":
		ops = firstOperand(ops)
	case (m == "rsbs" || m == "rsb") && strings.Count(ops, ",") == 1:
		ops += ",0"
	case m == "muls" && strings.Count(ops, ",") == 1:
		ops += "," + firstOperand(ops)
	}
	return m + cond, ops
}

func firstOperand(ops string) string {
	first, _, _ := strings.Cut(ops, ",")
	return first
}

// floatBits returns the width of a floating-point immediate the mnemonic
// takes, or 0.
func floatBits(m string) int {
	switch {
	case strings.HasSuffix(m, ".f64"):
		return 64
	case strings.HasSuffix(m, ".f32"):
		return 32
	}
	return 0
}

var (
	number   = regexp.MustCompile(`-?(?:0x[0-9a-f]+|[0-9]+)`)
	floatImm = regexp.MustCompile(`#-?[0-9]+\.[0-9]+e[-+][0-9]+`)
)

// normalizeOperands removes spacing, symbol annotations and the # sign,
// writes every number in decimal, and writes floating-point immediates as
// their IEEE bits (Ghidra prints vmov.f64 immediates as raw bits).
func normalizeOperands(ops string, floatWidth int) string {
	ops = strings.ToLower(ops)
	if i := strings.Index(ops, "<"); i >= 0 {
		ops = ops[:i]
	}
	ops = strings.Join(strings.Fields(ops), "")
	if floatWidth > 0 {
		ops = floatImm.ReplaceAllStringFunc(ops, func(f string) string {
			v, _ := strconv.ParseFloat(f[1:], 64)
			if floatWidth == 32 {
				return fmt.Sprint(math.Float32bits(float32(v)))
			}
			return fmt.Sprint(int64(math.Float64bits(v)))
		})
	}
	ops = number.ReplaceAllStringFunc(ops, func(n string) string {
		neg := strings.HasPrefix(n, "-")
		u, _ := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(n, "-"), "0x"), map[bool]int{true: 16, false: 10}[strings.Contains(n, "0x")], 64)
		v := int64(u)
		if neg {
			v = -v
		}
		if v < 0 && v >= -1<<31 {
			v = int64(uint32(v)) // LLVM prints some 32-bit immediates signed
		}
		return fmt.Sprint(v)
	})
	ops = strings.ReplaceAll(ops, "#", "")
	ops = strings.ReplaceAll(ops, "apsr_nzcv", "apsr")
	return strings.ReplaceAll(ops, ",0]", "]") // [sp,#0] is [sp]
}

// A divergence is a known difference between Ghidra's display of an
// instruction and LLVM's, where both decode the same instruction.
type divergence struct {
	name   string
	reason string
	match  func(got, want objdumpInsn, thumb bool) bool
}

var barrierOptions = []string{"#0", "#1", "oshst", "osh", "#4", "#5", "nshst", "nsh", "#8", "#9", "ishst", "ish", "#12", "#13", "st", "sy"}

// isaSyntax is how one ISA's listings are read and normalized, and the
// divergences known for it.
type isaSyntax struct {
	comment     string          // objdump's comment marker
	prefixes    map[string]bool // prefixes objdump prints on a line of their own
	normalize   func(objdumpInsn) (mnemonic, operands string)
	divergences []divergence
}

var (
	armSyntax = isaSyntax{
		comment:     "@",
		normalize:   func(in objdumpInsn) (string, string) { return normalize(in.mnemonic, in.operands) },
		divergences: armDivergences,
	}
	aarch64Syntax = isaSyntax{
		comment:     "//",
		normalize:   normalizeAArch64,
		divergences: aarch64Divergences,
	}
)

var (
	fmovImm      = regexp.MustCompile(`^([hsd])\d+,\s*#?(-?(?:0x[0-9a-f]+|[0-9]+\.[0-9]+))$`)
	dupScalar    = regexp.MustCompile(`^[bhsd]\d+,v\d+\.[bhsd]\[\d+\]$`)
	bitfieldImms = regexp.MustCompile(`^([wx])(\d+|zr),([wx])(\d+|zr),(\d+),(\d+)$`)
)

// normalizeAArch64 applies the ARM normalization, then folds the AArch64
// aliases LLVM prints and Ghidra does not: fmov immediates as their IEEE
// bits, bfi and bfxil as bfm, and mov from a vector element as dup.
func normalizeAArch64(in objdumpInsn) (string, string) {
	ops := strings.ToLower(strings.Join(strings.Fields(in.operands), ""))
	if strings.EqualFold(in.mnemonic, "fmov") {
		if f := fmovImm.FindStringSubmatch(ops); f != nil {
			var bits uint64
			if strings.Contains(f[2], ".") {
				v, _ := strconv.ParseFloat(f[2], 64)
				switch f[1] {
				case "s":
					bits = uint64(math.Float32bits(float32(v)))
				case "d":
					bits = math.Float64bits(v)
				}
			} else {
				neg := strings.HasPrefix(f[2], "-")
				u, _ := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(f[2], "-"), "0x"), 16, 64)
				if bits = u; neg {
					bits = -u // Ghidra prints the bits as a signed number
				}
			}
			ops = ops[:strings.Index(ops, ",")+1] + "#" + strconv.FormatUint(bits, 10)
		}
	}
	m, ops := normalize(in.mnemonic, ops)
	switch {
	case m == "mov" && dupScalar.MatchString(ops):
		m = "dup"
	case m == "bfi" || m == "bfxil":
		f := bitfieldImms.FindStringSubmatch(ops)
		if f == nil {
			break
		}
		size := map[string]int64{"w": 32, "x": 64}[f[1]]
		lsb, _ := strconv.ParseInt(f[5], 10, 64)
		width, _ := strconv.ParseInt(f[6], 10, 64)
		immr, imms := (size-lsb)%size, width-1
		if m == "bfxil" {
			immr, imms = lsb, lsb+width-1
		}
		m, ops = "bfm", fmt.Sprintf("%s%s,%s%s,%d,%d", f[1], f[2], f[3], f[4], immr, imms)
	}
	return m, ops
}

var aarch64Divergences = []divergence{
	{
		name:   "aarch64-unshifted-register-offset",
		reason: "for a register offset with S=0 and option LSL, addrExtendRegShift64 in AARCH64instructions.sinc concatenates a shift of #0x0 after the register",
		match: func(got, want objdumpInsn, _ bool) bool {
			return got.mnemonic == want.mnemonic &&
				strings.ReplaceAll(strings.ReplaceAll(got.operands, "#0x0]", "]"), " ", "") == strings.ReplaceAll(want.operands, " ", "")
		},
	},
}

// syntaxFor picks the syntax for a SLEIGH language id.
func syntaxFor(language string) isaSyntax {
	switch proc, _, _ := strings.Cut(language, ":"); proc {
	case "AARCH64":
		return aarch64Syntax
	case "x86":
		return x86Syntax
	}
	return armSyntax
}

var armDivergences = []divergence{
	{
		name:   "thumb-vcmp-nanx",
		reason: "the nanx subtable of ARMneon.sinc tests ARM field c0707 in Thumb mode too, so Thumb vcmp prints as vcmpe",
		match: func(got, want objdumpInsn, thumb bool) bool {
			return thumb && strings.HasPrefix(got.mnemonic, "vcmpe") &&
				strings.TrimPrefix(got.mnemonic, "vcmpe") == strings.TrimPrefix(want.mnemonic, "vcmp")
		},
	},
	{
		name:   "thumb-barrier-option",
		reason: "Thumb dmb/dsb print the raw 5-bit option field (#0x1f) where ARM mode prints its name (sy)",
		match: func(got, want objdumpInsn, thumb bool) bool {
			if !thumb || (got.mnemonic != "dmb" && got.mnemonic != "dsb") || got.mnemonic != want.mnemonic {
				return false
			}
			v, err := strconv.ParseUint(strings.TrimPrefix(got.operands, "#0x"), 16, 8)
			return err == nil && barrierOptions[v&0xf] == strings.TrimSpace(want.operands)
		},
	},
}

type corpusStats struct {
	insns, boundary, mnemonic, operands int
	diverged                            map[string]int
	failures                            []string
	divergences                         []string
}

func (st *corpusStats) add(o corpusStats) {
	st.insns += o.insns
	st.boundary += o.boundary
	st.mnemonic += o.mnemonic
	st.operands += o.operands
	for k, v := range o.diverged {
		st.diverged[k] += v
	}
}

func compareCorpusFile(t *testing.T, obj string) corpusStats {
	t.Helper()
	data, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := LoadUnrelocated(data)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDisassembler(prog)
	if err != nil {
		t.Fatal(err)
	}
	ref := readObjdump(t, strings.TrimSuffix(obj, ".o")+".objdump", syntaxFor(prog.Language))
	return compareListing(t, prog, d, ref)
}

// compareListing decodes prog's executable segments and compares each
// instruction with ref, objdump's listing of the same bytes.
func compareListing(t *testing.T, prog *Program, d *Disassembler, ref map[uint64]objdumpInsn) corpusStats {
	t.Helper()
	syn := syntaxFor(prog.Language)
	st := corpusStats{diverged: map[string]int{}}
	for _, seg := range prog.Segments {
		if seg.Perm&loader.PermX == 0 {
			continue
		}
		err := d.Range(seg.Addr, seg.End(), func(l Line) {
			mode := prog.ModeAt(l.Addr)
			if mode == loader.ModeData {
				return // literal pools; objdump decodes them as code
			}
			st.insns++
			want, ok := ref[l.Addr]
			if !ok {
				st.failures = append(st.failures, fmt.Sprintf("%#x: %s: objdump has no instruction here", l.Addr, l.Text()))
				return
			}
			if l.Insn == nil || l.Insn.Length != want.length {
				st.failures = append(st.failures, fmt.Sprintf("%#x: %s (%d bytes) | objdump %s %s (%d bytes)",
					l.Addr, l.Text(), len(l.Bytes), want.mnemonic, want.operands, want.length))
				return
			}
			st.boundary++
			got := objdumpInsn{addr: l.Addr, length: l.Insn.Length, mnemonic: l.Insn.Mnemonic, operands: l.Insn.Operands, bytes: l.Bytes}
			gm, gops := syn.normalize(got)
			wm, wops := syn.normalize(want)
			desc := fmt.Sprintf("%#x: %s | objdump %s %s", l.Addr, l.Text(), want.mnemonic, want.operands)
			if gm == wm && gops == wops {
				st.mnemonic++
				st.operands++
				return
			}
			for _, dv := range syn.divergences {
				if dv.match(got, want, mode == loader.ModeThumb) {
					st.mnemonic++
					st.operands++
					st.diverged[dv.name]++
					st.divergences = append(st.divergences, dv.name+": "+desc)
					return
				}
			}
			if gm == wm {
				st.mnemonic++
			}
			st.failures = append(st.failures, desc)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// TestCorpusTranslates builds the p-code of every corpus instruction. An
// instruction whose spec has no semantics (ErrUnimplemented) is counted,
// not failed; any other error fails, as does a varnode without a space.
func TestCorpusTranslates(t *testing.T) {
	objs, err := filepath.Glob(filepath.Join("..", "testdata", "synthetic", "*", "*.o"))
	if err != nil {
		t.Fatal(err)
	}
	insns, ops := map[string]int{}, map[string]int{}
	unimpl := map[string]map[string]int{}
	for _, obj := range objs {
		data, err := os.ReadFile(obj)
		if err != nil {
			t.Fatal(err)
		}
		prog, err := LoadUnrelocated(data)
		if err != nil {
			t.Fatal(err)
		}
		d, err := NewDisassembler(prog)
		if err != nil {
			t.Fatal(err)
		}
		name, _ := filepath.Rel(filepath.Join("..", "testdata", "synthetic"), obj)
		dir := filepath.Dir(name)
		for _, seg := range prog.Segments {
			if seg.Perm&loader.PermX == 0 {
				continue
			}
			err := d.Range(seg.Addr, seg.End(), func(l Line) {
				if l.Insn == nil {
					return
				}
				insns[dir]++
				_, pc, err := d.Translate(l.Addr)
				if errors.Is(err, sleigh.ErrUnimplemented) {
					if unimpl[dir] == nil {
						unimpl[dir] = map[string]int{}
					}
					unimpl[dir][l.Insn.Mnemonic]++
					return
				}
				if err != nil {
					t.Errorf("%s %#x %s: %v", name, l.Addr, l.Text(), err)
					return
				}
				for _, op := range pc {
					vns := op.In
					if op.Out != nil {
						vns = append([]sleigh.Varnode{*op.Out}, vns...)
					}
					for _, v := range vns {
						if v.Space == nil || v.Size <= 0 {
							t.Errorf("%s %#x %s: bad varnode in %s", name, l.Addr, l.Text(), op.Op)
						}
					}
				}
				ops[dir] += len(pc)
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	dirs := make([]string, 0, len(insns))
	for d := range insns {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		n := 0
		for _, c := range unimpl[d] {
			n += c
		}
		t.Logf("%-9s %5d instructions, %6d p-code ops, %d without semantics %v", d, insns[d], ops[d], n, unimpl[d])
	}
}

func TestCorpusMatchesObjdump(t *testing.T) {
	objs, err := filepath.Glob(filepath.Join("..", "testdata", "synthetic", "*", "*.o"))
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) == 0 {
		t.Fatal("no corpus objects; run make corpus")
	}
	verbose := os.Getenv("CORPUS_VERBOSE") != ""
	perDir := map[string]*corpusStats{}
	failures := 0
	for _, obj := range objs {
		st := compareCorpusFile(t, obj)
		name, _ := filepath.Rel(filepath.Join("..", "testdata", "synthetic"), obj)
		for _, f := range st.failures {
			t.Errorf("%s %s", name, f)
		}
		if verbose {
			for _, d := range st.divergences {
				t.Logf("%s %s", name, d)
			}
		}
		failures += len(st.failures)
		dir := filepath.Dir(name)
		if perDir[dir] == nil {
			perDir[dir] = &corpusStats{diverged: map[string]int{}}
		}
		perDir[dir].add(st)
	}

	total := corpusStats{diverged: map[string]int{}}
	dirs := make([]string, 0, len(perDir))
	for d := range perDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		st := perDir[d]
		pct := func(n int) float64 { return 100 * float64(n) / float64(max(st.insns, 1)) }
		t.Logf("%-9s %5d instructions: boundaries %.1f%%, mnemonics %.1f%%, operands %.1f%%",
			d, st.insns, pct(st.boundary), pct(st.mnemonic), pct(st.operands))
		total.add(*st)
	}
	t.Logf("%d instructions in %d objects", total.insns, len(objs))

	reasons := map[string]string{}
	for _, syn := range []isaSyntax{armSyntax, aarch64Syntax, x86Syntax} {
		for _, dv := range syn.divergences {
			reasons[dv.name] = dv.reason
		}
	}
	names := make([]string, 0, len(total.diverged))
	for n := range total.diverged {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t.Logf("known divergence %s: %d instructions (%s)", n, total.diverged[n], reasons[n])
	}
	if failures > 0 {
		t.Errorf("%d instructions differ from objdump", failures)
	}
}
