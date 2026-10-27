package engine

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/irexec"
	"github.com/stohirov/decompile-anything/internal/loader"
)

// The lifter gate: every corpus function runs in the IR interpreter on the
// inputs recorded in testdata/synthetic/vectors.jsonl, and must produce
// the results the same C code produced natively on the host (see
// testdata/synthetic/harness). Arguments go in as the target's calling
// convention passes them; calls to externals (C runtime helpers, printf,
// the switch callbacks) run as Go hooks. Results, floating point included,
// must match to the bit, except where a vendored spec is known to differ
// from the hardware (execDivergences below).

// execDivergence names a case where the spec's semantics differ from what the
// processor does, so the interpreter faithfully gets a different result.
type execDivergence struct {
	name, why string
	match     func(dir string, v vector) bool
}

var execDivergences = []execDivergence{{
	name: "x86-bsr-zero",
	why:  "Ghidra's BSR writes 31 to the destination when the source is 0; processors leave it unchanged, and clang's clz relies on that",
	match: func(dir string, v vector) bool {
		return dir == "x86-64" && v.Fn == "clz" && parseUint(v.Args[0]) == 0
	},
}}

func parseUint(s string) uint64 {
	x, _ := strconv.ParseUint(s, 0, 64)
	return x
}

type vector struct {
	Fn    string   `json:"fn"`
	Sig   string   `json:"sig"`
	Args  []string `json:"args"`
	Bufs  []vbuf   `json:"bufs"`
	Ret   string   `json:"ret"`
	Calls []string `json:"calls"`
	Out   string   `json:"out"`
}

type vbuf struct {
	Type string   `json:"type"`
	In   []uint32 `json:"in"`
	Out  []uint32 `json:"out"`
}

func readVectors(t *testing.T) []vector {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "testdata", "synthetic", "vectors.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []vector
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var v vector
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatalf("vectors: %v", err)
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

const (
	execStack    = 0x7ff00000
	execData     = 0x40000000 // buffer i lives at execData + i*execBufSpan
	execBufSpan  = 0x1000
	execCallback = 0x50000000
	execSteps    = 5_000_000
)

// run is one vector run against one function.
type run struct {
	t      *testing.T
	a      *Analysis
	m      *irexec.Machine
	cc     callConv
	calls  []string
	output []byte
}

func f32(x uint64) float32 { return math.Float32frombits(uint32(x)) }
func f64(x uint64) float64 { return math.Float64frombits(x) }
func b32(f float32) uint64 { return uint64(math.Float32bits(f)) }
func b64(f float64) uint64 { return math.Float64bits(f) }

func (r *run) cstring(addr uint64) string {
	var b []byte
	for i := uint64(0); i < 4096; i++ {
		c, err := r.m.Load(ir.SpaceRAM, addr+i, 1)
		if err != nil || c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// printf formats with the conversions the corpus uses.
func (r *run) printf() {
	format := r.cstring(r.cc.intArg(0))
	next := 1
	argw := func() uint64 {
		next++
		return r.cc.intArg(next - 1)
	}
	var out strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 == len(format) {
			out.WriteByte(format[i])
			continue
		}
		i++
		switch format[i] {
		case 'd':
			fmt.Fprintf(&out, "%d", int32(argw()))
		case 'u':
			fmt.Fprintf(&out, "%d", uint32(argw()))
		case 'x':
			fmt.Fprintf(&out, "%x", uint32(argw()))
		case 's':
			out.WriteString(r.cstring(argw()))
		case '%':
			out.WriteByte('%')
		default:
			r.t.Fatalf("printf: unsupported conversion %%%c", format[i])
		}
	}
	r.output = append(r.output, out.String()...)
	r.cc.setRet(uint64(out.Len()))
}

// hooks returns Go implementations of the externals the corpus calls.
// Each ends as the function's return instruction would.
func (r *run) hooks() map[string]irexec.Hook {
	c := r.cc
	arg := c.intArg
	record := func(name string) func() {
		return func() { r.calls = append(r.calls, name) }
	}
	memcpy := func() {
		b, err := r.m.ReadBytes(ir.SpaceRAM, arg(1), int(arg(2)))
		r.must(err)
		r.must(r.m.WriteBytes(ir.SpaceRAM, arg(0), b))
	}
	hooks := map[string]func(){
		"on_a": record("on_a"), "on_b": record("on_b"), "on_c": record("on_c"),
		"printf": func() {
			r.calls = append(r.calls, "printf")
			r.printf()
		},
		"memcpy": memcpy,
		"strlen": func() { c.setRet(uint64(len(r.cstring(arg(0))))) },
	}
	// ARM EABI run-time helpers take and return values in core registers.
	if arm, ok := c.(*aapcs); ok {
		pair := func(lo, hi int) uint64 { return arg(lo) | arg(hi)<<32 }
		ret2 := func(x uint64) {
			arm.set("r0", x&0xffffffff)
			arm.set("r1", x>>32)
		}
		f2 := func(op func(a, b float32) float32) func() {
			return func() { c.setRet(b32(op(f32(arg(0)), f32(arg(1))))) }
		}
		d2 := func(op func(a, b float64) float64) func() {
			return func() { ret2(b64(op(f64(pair(0, 1)), f64(pair(2, 3))))) }
		}
		divmod := func(signed bool) func() {
			return func() {
				a, b := arg(0), arg(1)
				if b == 0 {
					r.t.Fatal("division by zero in a runtime helper")
				}
				q, rem := uint32(a)/uint32(b), uint32(a)%uint32(b)
				if signed {
					q, rem = uint32(int32(a)/int32(b)), uint32(int32(a)%int32(b))
				}
				ret2(uint64(q) | uint64(rem)<<32)
			}
		}
		for name, h := range map[string]func(){
			"__aeabi_memcpy": memcpy,
			"__aeabi_idiv":   divmod(true), "__aeabi_idivmod": divmod(true),
			"__aeabi_uidiv": divmod(false), "__aeabi_uidivmod": divmod(false),
			"__aeabi_fadd": f2(func(a, b float32) float32 { return a + b }),
			"__aeabi_fsub": f2(func(a, b float32) float32 { return a - b }),
			"__aeabi_fmul": f2(func(a, b float32) float32 { return a * b }),
			"__aeabi_fdiv": f2(func(a, b float32) float32 { return a / b }),
			"__aeabi_dadd": d2(func(a, b float64) float64 { return a + b }),
			"__aeabi_dsub": d2(func(a, b float64) float64 { return a - b }),
			"__aeabi_dmul": d2(func(a, b float64) float64 { return a * b }),
			"__aeabi_ddiv": d2(func(a, b float64) float64 { return a / b }),
			"__aeabi_fcmpgt": func() {
				if f32(arg(0)) > f32(arg(1)) {
					c.setRet(1)
				} else {
					c.setRet(0)
				}
			},
			"__aeabi_f2iz": func() { c.setRet(uint64(uint32(int32(f32(arg(0)))))) },
			"__aeabi_i2f":  func() { c.setRet(b32(float32(int32(arg(0))))) },
			"__aeabi_f2d":  func() { ret2(b64(float64(f32(arg(0))))) },
		} {
			hooks[name] = h
		}
	}
	out := map[string]irexec.Hook{}
	for name, h := range hooks {
		out[name] = func(*irexec.Machine) error {
			h()
			c.leave()
			return nil
		}
	}
	return out
}

func parseHex(t *testing.T, s string) uint64 {
	t.Helper()
	x, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		t.Fatalf("vector value %q: %v", s, err)
	}
	return x
}

// place writes buffer b at addr and returns the pointer the function gets.
func (r *run) place(b vbuf, addr uint64) uint64 {
	ptr := uint64(r.a.Arch.PointerSize)
	switch b.Type {
	case "b": // bytes packed little-endian into words
		var bytes []byte
		for _, w := range b.In {
			bytes = append(bytes, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
		}
		r.must(r.m.WriteBytes(ir.SpaceRAM, addr, bytes))
	case "list": // struct node { struct node *next; int value; unsigned char tag; }
		n := len(b.In) / 2
		if n == 0 {
			return 0
		}
		size := (ptr + 5 + ptr - 1) / ptr * ptr
		for i := range n {
			node := addr + uint64(i)*size
			var next uint64
			if i+1 < n {
				next = node + size
			}
			r.must(r.m.Store(ir.SpaceRAM, node, int(ptr), next))
			r.must(r.m.Store(ir.SpaceRAM, node+ptr, 4, uint64(b.In[2*i])))
			r.must(r.m.Store(ir.SpaceRAM, node+ptr+4, 1, uint64(b.In[2*i+1])))
		}
	default: // int32 or float words
		for i, w := range b.In {
			r.must(r.m.Store(ir.SpaceRAM, addr+4*uint64(i), 4, uint64(w)))
		}
	}
	return addr
}

func (r *run) must(err error) {
	if err != nil {
		r.t.Fatal(err)
	}
}

// execute runs vector v on fn and returns a mismatch description, "" on
// success, or an error wrapping irexec.ErrUnsupported to skip.
func execute(t *testing.T, a *Analysis, fn *Function, v vector, dir string) (string, error) {
	m := irexec.New(a.Arch, a.Functions)
	m.StepLimit = execSteps
	for _, s := range a.Program.Segments {
		if err := m.WriteBytes(ir.SpaceRAM, s.Addr, s.Data); err != nil {
			return "", err
		}
	}
	cc, err := newCallConv(a, m, dir)
	if err != nil {
		return "", err
	}
	r := &run{t: t, a: a, m: m, cc: cc}
	hooks := r.hooks()
	for _, s := range a.Program.Symbols {
		if s.Kind != loader.SymImport {
			continue
		}
		h, ok := hooks[s.Name]
		if !ok {
			return "", fmt.Errorf("no hook for %s: %w", s.Name, irexec.ErrUnsupported)
		}
		m.Hooks[s.Addr] = h
	}
	for name, op := range userOps {
		m.UserOps[name] = op
	}
	m.Hooks[execCallback] = func(*irexec.Machine) error {
		cc.setRet(uint64(uint32(int32(cc.intArg(0))*3 - int32(cc.intArg(1)))))
		cc.leave()
		return nil
	}

	ret, params, _ := strings.Cut(v.Sig, ":")
	ptrs := make([]uint64, len(v.Bufs))
	for i, b := range v.Bufs {
		ptrs[i] = r.place(b, execData+uint64(i)*execBufSpan)
	}
	for i, s := range v.Args {
		var x uint64
		switch {
		case params[i] == 'p':
			n, _ := strconv.Atoi(strings.TrimPrefix(s, "b"))
			x = ptrs[n]
		case params[i] == 'F':
			x = execCallback
		default:
			x = parseHex(t, s)
		}
		if err := r.cc.arg(params[i], x); err != nil {
			return "", err
		}
	}
	cc.enter(execStack)

	if err := m.Call(fn.Entry); err != nil {
		return "", err
	}

	var diffs []string
	if ret[0] != 'v' {
		got, want := r.cc.ret(ret[0]), parseHex(t, v.Ret)
		if got != want {
			diffs = append(diffs, fmt.Sprintf("returned %#x, want %#x", got, want))
		}
	}
	for i, b := range v.Bufs {
		for j, w := range b.Out {
			got, err := m.Load(ir.SpaceRAM, ptrs[i]+4*uint64(j), 4)
			r.must(err)
			if uint32(got) != w {
				diffs = append(diffs, fmt.Sprintf("buffer %d word %d = %#x, want %#x", i, j, got, w))
				break
			}
		}
	}
	if strings.Join(r.calls, ",") != strings.Join(v.Calls, ",") {
		diffs = append(diffs, fmt.Sprintf("called %v, want %v", r.calls, v.Calls))
	}
	if got := hex.EncodeToString(r.output); got != v.Out {
		diffs = append(diffs, fmt.Sprintf("printed %q, want %q", r.output, v.Out))
	}
	return strings.Join(diffs, "; "), nil
}

func execDivergenceFor(dir string, v vector) *execDivergence {
	for i := range execDivergences {
		if execDivergences[i].match(dir, v) {
			return &execDivergences[i]
		}
	}
	return nil
}

// userOps gives meaning to the ARM spec's opaque operations the corpus
// reaches. Exclusive monitors always succeed: the interpreter runs one
// thread.
var userOps = map[string]irexec.UserOp{
	"hasExclusiveAccess":   func([]uint64, []int, uint64, int) (uint64, error) { return 1, nil },
	"ExclusiveMonitorPass": func([]uint64, []int, uint64, int) (uint64, error) { return 1, nil },
	// The status a store-exclusive writes back: 0 for success.
	"ExclusiveMonitorsStatus": func([]uint64, []int, uint64, int) (uint64, error) { return 0, nil },
	// NEON_saba(Vd, Vn, Vm, esize): Vd + |Vn - Vm| per signed lane.
	"NEON_saba": func(in []uint64, sizes []int, _ uint64, _ int) (uint64, error) {
		return absDiff([]uint64{in[1], in[2], in[3], 0}, sizes[1:], in[0]), nil
	},
	// VectorSignedToFloat(Vm, esize): each lane, a signed integer, to float.
	"VectorSignedToFloat": func(in []uint64, sizes []int, _ uint64, _ int) (uint64, error) {
		return lanes(in[0], sizes[0], 4, func(x uint64) uint64 { return b32(float32(int32(x))) }), nil
	},
	// VectorAbsoluteDifference(Vn, Vm, esize, unsigned)
	"VectorAbsoluteDifference": func(in []uint64, sizes []int, _ uint64, _ int) (uint64, error) {
		return absDiff(in, sizes, 0), nil
	},
	// VectorAbsoluteDifferenceAndAccumulate(Vn, Vm, esize, unsigned) adds
	// into the destination.
	"VectorAbsoluteDifferenceAndAccumulate": func(in []uint64, sizes []int, old uint64, _ int) (uint64, error) {
		return absDiff(in, sizes, old), nil
	},
}

// absDiff computes |Vn - Vm| per lane, added to the lanes of acc.
func absDiff(in []uint64, sizes []int, acc uint64) uint64 {
	esize := int(in[2])
	var r uint64
	for i := 0; i < sizes[0]/esize; i++ {
		sh := 8 * esize * i
		a, b := ir.SignExtend(in[0]>>sh, esize), ir.SignExtend(in[1]>>sh, esize)
		if in[3] != 0 {
			a, b = int64(in[0]>>sh&ir.Mask(esize)), int64(in[1]>>sh&ir.Mask(esize))
		}
		d := a - b
		if d < 0 {
			d = -d
		}
		r |= (uint64(d) + acc>>sh) & ir.Mask(esize) << sh
	}
	return r
}

// lanes applies f to each esize-byte lane of a size-byte vector.
func lanes(v uint64, size, esize int, f func(uint64) uint64) uint64 {
	var r uint64
	for i := 0; i < size/esize; i++ {
		sh := 8 * esize * i
		r |= f(v>>sh&ir.Mask(esize)) & ir.Mask(esize) << sh
	}
	return r
}

func TestIRMatchesNative(t *testing.T) {
	vectors := readVectors(t)
	byFn := map[string][]vector{}
	for _, v := range vectors {
		byFn[v.Fn] = append(byFn[v.Fn], v)
	}
	objs, err := filepath.Glob(filepath.Join("..", "testdata", "synthetic", "*", "*.o"))
	if err != nil {
		t.Fatal(err)
	}
	ran, failed := 0, 0
	skipped := map[string]int{}
	diverged := map[string]int{}
	covered := map[string]bool{}
	for _, obj := range objs {
		dir := filepath.Base(filepath.Dir(obj))
		if strings.HasPrefix(filepath.Base(obj), "stress-asm") {
			continue // hand-written instructions, no C functions
		}
		data, err := os.ReadFile(obj)
		if err != nil {
			t.Fatal(err)
		}
		prog, err := Load(data)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(prog, false)
		if err != nil {
			t.Fatal(err)
		}
		name, _ := filepath.Rel(filepath.Join("..", "testdata", "synthetic"), obj)
		for _, fn := range a.Functions {
			cases := byFn[fn.Name]
			if len(cases) == 0 {
				t.Errorf("%s: no vectors for %s", name, fn.Name)
				continue
			}
			for _, v := range cases {
				diff, err := execute(t, a, fn, v, dir)
				switch {
				case errors.Is(err, irexec.ErrUnsupported):
					skipped[fmt.Sprintf("%s: %v", fn.Name, err)]++
					continue
				case err != nil:
					diff = err.Error()
				}
				if diff != "" {
					if d := execDivergenceFor(dir, v); d != nil {
						diverged[d.name]++
						continue
					}
					failed++
					if failed <= 40 {
						t.Errorf("%s %s%v: %s", name, fn.Name, v.Args, diff)
					}
					continue
				}
				ran++
				covered[fn.Name] = true
			}
		}
	}
	t.Logf("%d runs matched native results", ran)
	for _, d := range execDivergences {
		if n := diverged[d.name]; n > 0 {
			t.Logf("known divergence %s: %d runs (%s)", d.name, n, d.why)
		}
	}
	reasons := make([]string, 0, len(skipped))
	for r := range skipped {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		t.Logf("skipped %d: %s", skipped[r], r)
	}
	if failed > 40 {
		t.Errorf("... and %d more mismatches", failed-40)
	}
	for fn := range byFn {
		if !covered[fn] {
			t.Errorf("no object ran %s", fn)
		}
	}
}
