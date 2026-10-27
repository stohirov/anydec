package engine

import (
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"testing"

	"github.com/stohirov/decompile-anything/internal/sleigh"
)

// P-code is checked by running it: a small interpreter executes corpus
// functions on concrete inputs, and the results must match the C source's
// semantics, written again in Go below. Only integer leaf functions run;
// calls are out of scope until the loader applies relocations.

var errUnsupported = errors.New("unsupported by the test interpreter")

// machine is a p-code interpreter over byte-addressed spaces.
type machine struct {
	t      *testing.T
	d      *Disassembler
	prog   *Program
	mem    map[int]map[uint64]byte // space index -> bytes
	big    bool
	cache  map[uint64]translated
	steps  int
	retPC  uint64
	thumbs map[uint64]bool
}

type translated struct {
	in  *sleigh.Instruction
	ops []sleigh.PcodeOp
}

const (
	stackTop  = 0x7ff00000
	dataBase  = 0x40000000
	returnPC  = 0x0dead000
	stepLimit = 200000
)

func newMachine(t *testing.T, d *Disassembler, p *Program) *machine {
	m := &machine{t: t, d: d, prog: p, mem: map[int]map[uint64]byte{}, big: p.BigEndian, cache: map[uint64]translated{}}
	ram := d.Spec().DefaultSpace
	for _, s := range p.Segments {
		for i, b := range s.Data {
			m.store(ram.Index, s.Addr+uint64(i), 1, uint64(b))
		}
	}
	return m
}

func (m *machine) space(i int) map[uint64]byte {
	s := m.mem[i]
	if s == nil {
		s = map[uint64]byte{}
		m.mem[i] = s
	}
	return s
}

func (m *machine) load(space int, off uint64, size int) uint64 {
	s := m.space(space)
	var v uint64
	for i := 0; i < size; i++ {
		b := uint64(s[off+uint64(i)])
		if m.big {
			v = v<<8 | b
		} else {
			v |= b << (8 * i)
		}
	}
	return v
}

func (m *machine) store(space int, off uint64, size int, v uint64) {
	s := m.space(space)
	for i := 0; i < size; i++ {
		shift := 8 * i
		if m.big {
			shift = 8 * (size - 1 - i)
		}
		s[off+uint64(i)] = byte(v >> shift)
	}
}

func (m *machine) get(v sleigh.Varnode) uint64 {
	if v.Size > 8 {
		panic(fmt.Errorf("%d-byte varnode: %w", v.Size, errUnsupported))
	}
	if v.Space.Kind == sleigh.SpaceConstant {
		return v.Offset
	}
	return m.load(v.Space.Index, v.Offset, v.Size)
}

func (m *machine) set(v *sleigh.Varnode, x uint64) {
	if v.Size > 8 {
		panic(fmt.Errorf("%d-byte varnode: %w", v.Size, errUnsupported))
	}
	m.store(v.Space.Index, v.Offset, v.Size, x&mask(v.Size))
}

func (m *machine) reg(name string) *sleigh.Varnode {
	r := m.d.Spec().Register(name)
	if r == nil {
		m.t.Fatalf("no register %s", name)
	}
	return &sleigh.Varnode{Space: r.Space, Offset: r.Offset, Size: r.Size}
}

func mask(size int) uint64 {
	if size >= 8 {
		return ^uint64(0)
	}
	return 1<<(8*size) - 1
}

func signed(v uint64, size int) int64 {
	sh := 64 - 8*size
	return int64(v<<sh) >> sh
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// call runs the function at entry with the given arguments in r0-r3 and
// returns r0 and r1.
func (m *machine) call(entry uint64, args ...uint64) (r0, r1 uint64, err error) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(error)
			if !ok || !errors.Is(e, errUnsupported) {
				panic(r)
			}
			err = e
		}
	}()
	for i, a := range args {
		m.set(m.reg(fmt.Sprintf("r%d", i)), a)
	}
	m.set(m.reg("sp"), stackTop)
	m.set(m.reg("lr"), returnPC)
	pc := entry
	for m.steps = 0; pc != returnPC; m.steps++ {
		if m.steps > stepLimit {
			return 0, 0, fmt.Errorf("no return after %d instructions", stepLimit)
		}
		next, err := m.step(pc)
		if err != nil {
			return 0, 0, err
		}
		pc = next
	}
	return m.get(*m.reg("r0")), m.get(*m.reg("r1")), nil
}

// step executes one instruction and returns the next pc.
func (m *machine) step(pc uint64) (uint64, error) {
	tr, ok := m.cache[pc]
	if !ok {
		in, ops, err := m.d.Translate(pc)
		if err != nil {
			return 0, err
		}
		tr = translated{in, ops}
		m.cache[pc] = tr
	}
	fall := pc + uint64(tr.in.Length)
	if r := m.prog.RelocsIn(pc, fall); len(r) > 0 {
		panic(fmt.Errorf("unrelocated reference to %s at %#x: %w", r[0].Symbol, pc, errUnsupported))
	}
	for i := 0; i < len(tr.ops); i++ {
		op := tr.ops[i]
		in := func(k int) uint64 { return m.get(op.In[k]) }
		size := 0
		if op.Out != nil {
			size = op.Out.Size
		}
		isz := 0
		if len(op.In) > 0 {
			isz = op.In[0].Size
		}
		var out uint64
		switch op.Op {
		case sleigh.OpCopy:
			out = in(0)
		case sleigh.OpLoad:
			out = m.load(int(op.In[0].Offset), in(1), size)
		case sleigh.OpStore:
			m.store(int(op.In[0].Offset), in(1), op.In[2].Size, in(2))
			continue
		case sleigh.OpBranch, sleigh.OpCBranch:
			if op.Op == sleigh.OpCBranch && in(1) == 0 {
				continue
			}
			if op.In[0].Space.Kind == sleigh.SpaceConstant {
				i += int(signed(op.In[0].Offset, op.In[0].Size)) - 1 // relative to this op
				continue
			}
			return op.In[0].Offset, nil
		case sleigh.OpBranchInd, sleigh.OpReturn:
			return in(0) &^ 1, nil
		case sleigh.OpCall, sleigh.OpCallInd:
			panic(fmt.Errorf("call at %#x: %w", pc, errUnsupported))
		case sleigh.OpCallOther:
			if op.Out != nil {
				panic(fmt.Errorf("%s at %#x: %w", m.d.Spec().UserOp(int(op.In[0].Offset)), pc, errUnsupported))
			}
			continue
		case sleigh.OpIntEqual:
			out = b2u(in(0) == in(1))
		case sleigh.OpIntNotEqual:
			out = b2u(in(0) != in(1))
		case sleigh.OpIntSLess:
			out = b2u(signed(in(0), isz) < signed(in(1), isz))
		case sleigh.OpIntSLessEqual:
			out = b2u(signed(in(0), isz) <= signed(in(1), isz))
		case sleigh.OpIntLess:
			out = b2u(in(0) < in(1))
		case sleigh.OpIntLessEqual:
			out = b2u(in(0) <= in(1))
		case sleigh.OpIntZExt:
			out = in(0)
		case sleigh.OpIntSExt:
			out = uint64(signed(in(0), isz))
		case sleigh.OpIntAdd:
			out = in(0) + in(1)
		case sleigh.OpIntSub:
			out = in(0) - in(1)
		case sleigh.OpIntCarry:
			out = b2u((in(0)+in(1))&mask(isz) < in(0))
		case sleigh.OpIntSCarry:
			a, b := signed(in(0), isz), signed(in(1), isz)
			r := signed(uint64(a+b)&mask(isz), isz)
			out = b2u((a >= 0) == (b >= 0) && (r >= 0) != (a >= 0))
		case sleigh.OpIntSBorrow:
			a, b := signed(in(0), isz), signed(in(1), isz)
			r := signed(uint64(a-b)&mask(isz), isz)
			out = b2u((a >= 0) != (b >= 0) && (r >= 0) != (a >= 0))
		case sleigh.OpInt2Comp:
			out = -in(0)
		case sleigh.OpIntNegate:
			out = ^in(0)
		case sleigh.OpIntXor:
			out = in(0) ^ in(1)
		case sleigh.OpIntAnd:
			out = in(0) & in(1)
		case sleigh.OpIntOr:
			out = in(0) | in(1)
		case sleigh.OpIntLeft:
			if s := in(1); s < 64 {
				out = in(0) << s
			}
		case sleigh.OpIntRight:
			if s := in(1); s < 64 {
				out = in(0) >> s
			}
		case sleigh.OpIntSRight:
			s := min(in(1), 63)
			out = uint64(signed(in(0), isz) >> s)
		case sleigh.OpIntMult:
			out = in(0) * in(1)
		case sleigh.OpIntDiv:
			if in(1) == 0 {
				return 0, fmt.Errorf("division by zero at %#x", pc)
			}
			out = in(0) / in(1)
		case sleigh.OpIntSDiv:
			if in(1) == 0 {
				return 0, fmt.Errorf("division by zero at %#x", pc)
			}
			out = uint64(signed(in(0), isz) / signed(in(1), isz))
		case sleigh.OpIntRem:
			if in(1) == 0 {
				return 0, fmt.Errorf("division by zero at %#x", pc)
			}
			out = in(0) % in(1)
		case sleigh.OpIntSRem:
			if in(1) == 0 {
				return 0, fmt.Errorf("division by zero at %#x", pc)
			}
			out = uint64(signed(in(0), isz) % signed(in(1), isz))
		case sleigh.OpBoolNegate:
			out = in(0) ^ 1
		case sleigh.OpBoolXor:
			out = in(0) ^ in(1)
		case sleigh.OpBoolAnd:
			out = in(0) & in(1)
		case sleigh.OpBoolOr:
			out = in(0) | in(1)
		case sleigh.OpPiece:
			out = in(0)<<(8*op.In[1].Size) | in(1)
		case sleigh.OpSubpiece:
			out = in(0) >> (8 * in(1))
		case sleigh.OpPopCount:
			out = uint64(bits.OnesCount64(in(0)))
		case sleigh.OpLzCount:
			out = uint64(bits.LeadingZeros64(in(0)) - (64 - 8*isz))
		default:
			panic(fmt.Errorf("%s at %#x: %w", op.Op, pc, errUnsupported))
		}
		m.set(op.Out, out)
	}
	return fall, nil
}

// A pcodeCase runs one function on inputs and checks r0 (and r1 for
// 64-bit results) against want.
type pcodeCase struct {
	fn    string
	args  []uint64
	want  uint64
	wide  bool             // result is 64 bits in r0:r1
	setup func(m *machine) // initializes memory the arguments point to
}

func i32(v int32) uint64 { return uint64(uint32(v)) }

func words(m *machine, addr uint64, vals ...int32) {
	for i, v := range vals {
		m.store(m.d.Spec().DefaultSpace.Index, addr+4*uint64(i), 4, uint64(uint32(v)))
	}
}

var pcodeCases = map[string][]pcodeCase{
	"arith": {
		{fn: "add", args: []uint64{2, 40}, want: 42},
		{fn: "add", args: []uint64{i32(-5), 3}, want: i32(-2)},
		{fn: "mul_add", args: []uint64{6, 7, i32(-2)}, want: 40},
		{fn: "shifts", args: []uint64{0x80000001, 4}, want: (0x80000001<<4 ^ 0x80000001>>28) & 0xffffffff},
		{fn: "clamp", args: []uint64{i32(-3), 0, 10}, want: 0},
		{fn: "clamp", args: []uint64{7, 0, 10}, want: 7},
		{fn: "clamp", args: []uint64{99, 0, 10}, want: 10},
		{fn: "wide_add", args: []uint64{0xffffffff, 0, 1, 0}, want: 0x100000000, wide: true},
	},
	"loops": {
		{fn: "sum", args: []uint64{dataBase, 5}, want: i32(15 - 7), setup: func(m *machine) {
			words(m, dataBase, 1, 2, 3, 4, -2)
		}},
		{fn: "sum", args: []uint64{dataBase, 0}, want: 0},
		{fn: "sum", args: []uint64{dataBase, 9}, want: 45, setup: func(m *machine) {
			words(m, dataBase, 1, 2, 3, 4, 5, 6, 7, 8, 9)
		}},
		{fn: "find", args: []uint64{dataBase, 4, 30}, want: 2, setup: func(m *machine) {
			words(m, dataBase, 10, 20, 30, 40)
		}},
		{fn: "find", args: []uint64{dataBase, 4, 31}, want: i32(-1), setup: func(m *machine) {
			words(m, dataBase, 10, 20, 30, 40)
		}},
		{fn: "strlen_", args: []uint64{dataBase}, want: 5, setup: func(m *machine) {
			for i, c := range []byte("hello\x00") {
				m.store(m.d.Spec().DefaultSpace.Index, dataBase+uint64(i), 1, uint64(c))
			}
		}},
		{fn: "collatz", args: []uint64{27}, want: 111},
	},
	"bits": {
		{fn: "popcount", args: []uint64{0xf0f00001}, want: 9},
		{fn: "bswap", args: []uint64{0x11223344}, want: 0x44332211},
		{fn: "clz", args: []uint64{0x00010000}, want: 15},
		{fn: "clz", args: []uint64{0}, want: 32},
		{fn: "mul64", args: []uint64{0xffffffff, 0, 0xffffffff, 0}, want: 0xfffffffe00000001, wide: true},
		{fn: "smull", args: []uint64{i32(-3), 1 << 30}, want: smullWant, wide: true},
		{fn: "rotl", args: []uint64{0x80000001, 1}, want: 3},
		{fn: "rotl", args: []uint64{0x12345678, 0}, want: 0x12345678},
		{fn: "extract", args: []uint64{0xffff0f80}, want: 0x1f},
		{fn: "insert", args: []uint64{0xffffffff, 0}, want: 0xfffff07f},
		{fn: "sext", args: []uint64{i32(-128)}, want: i32(-128)},
		{fn: "zext", args: []uint64{0x80}, want: 0x80},
	},
}

func TestPcodeExecutesCorpus(t *testing.T) {
	objs, err := filepath.Glob(filepath.Join("..", "testdata", "synthetic", "*", "*.o"))
	if err != nil {
		t.Fatal(err)
	}
	ran, skipped := 0, map[string]int{}
	for _, obj := range objs {
		base := filepath.Base(obj)
		src := base[:len(base)-len(filepath.Ext(base))]
		src = src[:len(src)-3] // strip -O2
		cases := pcodeCases[src]
		if len(cases) == 0 {
			continue
		}
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
		name, _ := filepath.Rel(filepath.Join("..", "testdata", "synthetic"), obj)
		for _, c := range cases {
			sym, ok := prog.Lookup(c.fn)
			if !ok {
				t.Fatalf("%s: no function %s", name, c.fn)
			}
			m := newMachine(t, d, prog)
			if c.setup != nil {
				c.setup(m)
			}
			r0, r1, err := m.call(sym.Addr, c.args...)
			if errors.Is(err, errUnsupported) {
				skipped[err.Error()]++
				continue
			}
			if err != nil {
				t.Errorf("%s %s%v: %v", name, c.fn, c.args, err)
				continue
			}
			got := r0 & 0xffffffff
			if c.wide {
				got |= r1 << 32
			}
			want := c.want
			if !c.wide {
				want &= 0xffffffff
			}
			if got != want {
				t.Errorf("%s %s%v = %#x, want %#x", name, c.fn, c.args, got, want)
			}
			ran++
		}
	}
	t.Logf("ran %d function cases", ran)
	for reason, n := range skipped {
		t.Logf("skipped %d: %s", n, reason)
	}
	if ran == 0 {
		t.Fatal("no cases ran")
	}
}

var smullA int64 = -3

// smullWant is (long long)-3 * (1 << 30), computed at run time because the
// constant does not convert to uint64.
var smullWant = uint64(smullA << 30)
