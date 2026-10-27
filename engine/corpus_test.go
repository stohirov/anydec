package engine

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stohirov/decompile-anything/internal/loader"
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
}

var objdumpLine = regexp.MustCompile(`^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2,8} )+)\s*\t(\S+)(?:\t(.*))?$`)

func readObjdump(t *testing.T, path string) map[uint64]objdumpInsn {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[uint64]objdumpInsn{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := objdumpLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		var in objdumpInsn
		in.addr, _ = strconv.ParseUint(m[1], 16, 64)
		in.length = len(strings.ReplaceAll(m[2], " ", "")) / 2
		in.mnemonic = m[3]
		in.operands, _, _ = strings.Cut(m[4], "@") // drop "@ imm = #..." comments
		out[in.addr] = in
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
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

var divergences = []divergence{
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
	prog, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDisassembler(prog)
	if err != nil {
		t.Fatal(err)
	}
	ref := readObjdump(t, strings.TrimSuffix(obj, ".o")+".objdump")
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
			got := objdumpInsn{l.Addr, l.Insn.Length, l.Insn.Mnemonic, l.Insn.Operands}
			gm, gops := normalize(got.mnemonic, got.operands)
			wm, wops := normalize(want.mnemonic, want.operands)
			desc := fmt.Sprintf("%#x: %s | objdump %s %s", l.Addr, l.Text(), want.mnemonic, want.operands)
			if gm == wm && gops == wops {
				st.mnemonic++
				st.operands++
				return
			}
			for _, dv := range divergences {
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

func TestCorpusMatchesObjdump(t *testing.T) {
	objs, err := filepath.Glob(filepath.Join("..", "testdata", "synthetic", "*", "*.o"))
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) == 0 {
		t.Fatal("no corpus objects; run make corpus")
	}
	verbose := os.Getenv("CORPUS_VERBOSE") != ""
	total := corpusStats{diverged: map[string]int{}}
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
		total.add(st)
	}
	pct := func(n int) float64 { return 100 * float64(n) / float64(total.insns) }
	t.Logf("%d instructions in %d objects: boundaries %.1f%%, mnemonics %.1f%%, operands %.1f%%",
		total.insns, len(objs), pct(total.boundary), pct(total.mnemonic), pct(total.operands))
	names := make([]string, 0, len(total.diverged))
	for n := range total.diverged {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, dv := range divergences {
			if dv.name == n {
				t.Logf("known divergence %s: %d instructions (%s)", n, total.diverged[n], dv.reason)
			}
		}
	}
	if failures > 0 {
		t.Errorf("%d instructions differ from objdump", failures)
	}
}
