package ssa

import (
	"strings"
	"testing"

	"github.com/stohirov/decompile-anything/internal/ir"
)

// A toy 32-bit machine: r0-r4 and sp in the register space, flags NG and
// OV, and RAX/EAX overlapping at 0x100.
func reg(off uint64, size uint8) ir.Varnode {
	return ir.Varnode{Space: ir.SpaceRegister, Offset: off, Size: size}
}

func k(v uint64, size uint8) ir.Varnode {
	return ir.Varnode{Space: ir.SpaceConst, Offset: v, Size: size}
}
func tmp(off uint64, size uint8) ir.Varnode {
	return ir.Varnode{Space: ir.SpaceUnique, Offset: off, Size: size}
}

var (
	r0, r1, r2, r3, r4 = reg(0, 4), reg(4, 4), reg(8, 4), reg(12, 4), reg(16, 4)
	sp                 = reg(0x34, 4)
	ng, ov             = reg(0x40, 1), reg(0x41, 1)
	rax, eax           = reg(0x100, 8), reg(0x100, 4)
	ram                = k(uint64(ir.SpaceRAM), 4)
)

var testABI = &ABI{
	SP: sp, IntParams: []ir.Varnode{r0, r1, r2, r3}, IntReturns: []ir.Varnode{r0, r1},
	Unaffected: []ir.Varnode{r4, sp}, StackParams: true, StackAlign: 4,
}

var testArch = &ir.Arch{Language: "TEST:LE:32:default", PointerSize: 4, Register: func(off uint64, size uint8) string {
	names := map[ir.Varnode]string{r0: "r0", r1: "r1", r2: "r2", r3: "r3", r4: "r4", sp: "sp", rax: "rax", eax: "eax"}
	return names[reg(off, size)]
}}

func op(code ir.Opcode, out *ir.Varnode, in ...ir.Varnode) ir.Op {
	return ir.Op{Code: code, Out: out, In: in}
}
func out(v ir.Varnode) *ir.Varnode { return &v }

// function builds an IR function from blocks of ops and successor lists;
// every op gets an instruction of its own.
func function(blocks [][]ir.Op, succ [][]int) *ir.Function {
	fn := &ir.Function{Name: "f"}
	addr := uint64(0x1000)
	for _, ops := range blocks {
		b := &ir.Block{Start: addr}
		for _, o := range ops {
			o.Origin = addr
			fn.Insns = append(fn.Insns, &ir.Insn{Addr: addr, Length: 4, Ops: []ir.Op{o}})
			b.Ops = append(b.Ops, o)
			addr += 4
		}
		fn.Blocks = append(fn.Blocks, b)
	}
	fn.Entry = fn.Blocks[0].Start
	for i, ss := range succ {
		for _, s := range ss {
			fn.Blocks[i].Succ = append(fn.Blocks[i].Succ, fn.Blocks[s])
			fn.Blocks[s].Pred = append(fn.Blocks[s].Pred, fn.Blocks[i])
		}
	}
	return fn
}

func build(t *testing.T, blocks [][]ir.Op, succ [][]int) *Func {
	t.Helper()
	fn := function(blocks, succ)
	if err := fn.Verify(); err != nil {
		t.Fatal(err)
	}
	f := Build(fn, testArch, testABI, nil)
	f.Simplify(nil)
	return f
}

func ret() ir.Op { return op(ir.OpReturn, nil, r4) }

// result is the value the first return block passes back in r0.
func result(f *Func) *Value {
	for _, b := range f.Blocks {
		if b.Kind == BlockReturn {
			return b.Results[0]
		}
	}
	return nil
}

func isInput(v *Value, r ir.Varnode) bool {
	return v.Op == OpInput && v.Var.Offset == int64(r.Offset) && v.Var.Size == int(r.Size)
}

func TestFlagsFoldIntoComparison(t *testing.T) {
	// cmp r0, r1; bge: N == V.
	f := build(t, [][]ir.Op{
		{
			op(ir.OpIntSub, out(tmp(0, 4)), r0, r1),
			op(ir.OpIntSLess, out(ng), tmp(0, 4), k(0, 4)),
			op(ir.OpIntSBorrow, out(ov), r0, r1),
			op(ir.OpIntEqual, out(tmp(8, 1)), ng, ov),
			op(ir.OpCBranch, nil, k(0, 4), tmp(8, 1)),
		},
		{op(ir.OpCopy, out(r0), k(1, 4)), ret()},
		{op(ir.OpCopy, out(r0), k(2, 4)), ret()},
	}, [][]int{{1, 2}, nil, nil})
	c := f.Blocks[0].Control
	if c.Op != ir.OpIntSLessEqual || !isInput(c.Args[0], r1) || !isInput(c.Args[1], r0) {
		t.Errorf("condition is %s, want r1 <= r0 signed\n%s", f.Format(c), f)
	}
}

func TestPartialRegisterWrite(t *testing.T) {
	// EAX = r1; RAX = zext(EAX); r0 = RAX's low half.
	f := build(t, [][]ir.Op{{
		op(ir.OpCopy, out(eax), r1),
		op(ir.OpIntZExt, out(rax), eax),
		op(ir.OpSubpiece, out(r0), rax, k(0, 4)),
		ret(),
	}}, [][]int{nil})
	if r := result(f); !isInput(r, r1) {
		t.Errorf("r0 = %s, want r1's input\n%s", f.ValueName(r), f)
	}
}

func TestLoopGetsPhi(t *testing.T) {
	// r0 = 0; while (r0 < r1) r0++;
	f := build(t, [][]ir.Op{
		{op(ir.OpCopy, out(r0), k(0, 4)), op(ir.OpBranch, nil, ir.Varnode{Space: ir.SpaceRAM, Offset: 0x1004, Size: 4})},
		{op(ir.OpIntSLess, out(tmp(0, 1)), r0, r1), op(ir.OpCBranch, nil, k(0, 4), tmp(0, 1))},
		{op(ir.OpIntAdd, out(r0), r0, k(1, 4)), op(ir.OpBranch, nil, ir.Varnode{Space: ir.SpaceRAM, Offset: 0x1008, Size: 4})},
		{ret()},
	}, [][]int{{1}, {2, 3}, {1}, nil})
	var phi *Value
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == ir.OpPhi {
				phi = v
			}
		}
	}
	if phi == nil {
		t.Fatalf("no phi:\n%s", f)
	}
	if c, ok := phi.Args[0].IsConst(); !ok || c != 0 || phi.Args[1].Op != ir.OpIntAdd || phi.Args[1].Args[0] != phi {
		t.Errorf("phi is %s\n%s", f.Format(phi), f)
	}
	if result(f) != phi {
		t.Errorf("loop result is not the phi\n%s", f)
	}
}

func TestStackPromotion(t *testing.T) {
	// sp -= 8; [sp+4] = r0; r1 = [sp+4]; r0 = r1 + 1
	f := build(t, [][]ir.Op{{
		op(ir.OpIntSub, out(sp), sp, k(8, 4)),
		op(ir.OpIntAdd, out(tmp(0, 4)), sp, k(4, 4)),
		op(ir.OpStore, nil, ram, tmp(0, 4), r0),
		op(ir.OpLoad, out(r1), ram, tmp(0, 4)),
		op(ir.OpIntAdd, out(r0), r1, k(1, 4)),
		ret(),
	}}, [][]int{nil})
	if !f.PromoteStack() {
		t.Fatalf("frame not promoted\n%s", f)
	}
	f.Simplify(nil)
	r := result(f)
	if r.Op != ir.OpIntAdd || !isInput(r.Args[0], r0) {
		t.Errorf("r0 = %s, want r0_in + 1\n%s", f.Format(r), f)
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == ir.OpLoad || v.Op == ir.OpStore {
				t.Errorf("memory access left after promotion: %s", f.Format(v))
			}
		}
	}
}

func TestEscapingFrameStaysMemory(t *testing.T) {
	// r0 = sp - 4 passed to a call: the callee may write the slot.
	f := build(t, [][]ir.Op{{
		op(ir.OpIntSub, out(r0), sp, k(4, 4)),
		op(ir.OpStore, nil, ram, r0, r1),
		op(ir.OpCall, nil, ir.Varnode{Space: ir.SpaceRAM, Offset: 0x2000, Size: 4}),
		op(ir.OpIntSub, out(tmp(0, 4)), sp, k(4, 4)),
		op(ir.OpLoad, out(r0), ram, tmp(0, 4)),
		ret(),
	}}, [][]int{nil})
	f.BindArgs(testABI, func(*Value) *Proto { return &Proto{Params: []Param{{Reg: r0, Size: 4}}} }, nil)
	if f.PromoteStack() {
		t.Errorf("promoted a frame whose address escapes\n%s", f)
	}
}

func TestExtendedDivisionNarrows(t *testing.T) {
	// x86 CDQ; IDIV: (sext(EAX) as EDX:EAX) / sext(r1), low half.
	f := build(t, [][]ir.Op{{
		op(ir.OpIntSExt, out(tmp(0, 8)), r0),
		op(ir.OpSubpiece, out(tmp(0x10, 4)), tmp(0, 8), k(4, 4)),
		op(ir.OpIntZExt, out(tmp(0x20, 8)), tmp(0x10, 4)),
		op(ir.OpIntLeft, out(tmp(0x20, 8)), tmp(0x20, 8), k(32, 4)),
		op(ir.OpIntZExt, out(tmp(0x30, 8)), r0),
		op(ir.OpIntOr, out(tmp(0x40, 8)), tmp(0x20, 8), tmp(0x30, 8)),
		op(ir.OpIntSExt, out(tmp(0x50, 8)), r1),
		op(ir.OpIntSDiv, out(tmp(0x60, 8)), tmp(0x40, 8), tmp(0x50, 8)),
		op(ir.OpSubpiece, out(r0), tmp(0x60, 8), k(0, 4)),
		ret(),
	}}, [][]int{nil})
	r := result(f)
	if r.Op != ir.OpIntSDiv || r.Size != 4 || !isInput(r.Args[0], r0) || !isInput(r.Args[1], r1) {
		t.Errorf("r0 = %s, want r0_in s/ r1_in on 4 bytes\n%s", f.Format(r), f)
	}
}

func TestStatusBitsReadBack(t *testing.T) {
	// A status word packs (r0 < r1) at bit 31 over the old word's low
	// bits; reading bit 31 back gives the comparison.
	f := build(t, [][]ir.Op{{
		op(ir.OpIntLess, out(tmp(0, 1)), r0, r1),
		op(ir.OpIntZExt, out(tmp(8, 4)), tmp(0, 1)),
		op(ir.OpIntLeft, out(tmp(8, 4)), tmp(8, 4), k(31, 4)),
		op(ir.OpIntAnd, out(tmp(0x10, 4)), r2, k(0x7fffffff, 4)),
		op(ir.OpIntOr, out(tmp(0x18, 4)), tmp(0x10, 4), tmp(8, 4)),
		op(ir.OpIntRight, out(tmp(0x20, 4)), tmp(0x18, 4), k(31, 4)),
		op(ir.OpIntAnd, out(r0), tmp(0x20, 4), k(1, 4)),
		ret(),
	}}, [][]int{nil})
	r := result(f)
	if r.Op != ir.OpIntZExt || r.Args[0].Op != ir.OpIntLess {
		t.Errorf("r0 = %s, want zext(r0 < r1)\n%s", f.Format(r), f)
	}
}

func TestPrototypeInference(t *testing.T) {
	// r0 + r2: r1 is unused but sits between, so it is a parameter too;
	// r0 is set, so the function returns a value.
	f := build(t, [][]ir.Op{{
		op(ir.OpIntAdd, out(r0), r0, r2),
		ret(),
	}}, [][]int{nil})
	ev := f.Gather(testABI, func(uint64) bool { return false }, nil)
	ps := ev.Params(testABI)
	if len(ps) != 3 || ps[0].Reg != r0 || ps[2].Reg != r2 {
		t.Errorf("params %+v", ps)
	}
	rets := f.InferReturns(testABI)
	if len(rets) != 1 || rets[0].Reg != r0 || rets[0].Size != 4 {
		t.Errorf("returns %+v", rets)
	}
	f.Proto = &Proto{Params: ps, Known: true}
	f.BindParams(ps)
	f.SetReturns(rets)
	if s := f.String(); !strings.HasPrefix(s, "f(r0_in, r1_in, r2_in) -> 4") {
		t.Errorf("prototype printed as %q", strings.SplitN(s, "\n", 2)[0])
	}
}

func TestPassThroughParameter(t *testing.T) {
	// g(x) { return h(x); } where h takes r0: r0 is g's parameter only
	// because h takes it.
	g := build(t, [][]ir.Op{{
		op(ir.OpCall, nil, ir.Varnode{Space: ir.SpaceRAM, Offset: 0x2000, Size: 4}),
		ret(),
	}}, [][]int{nil})
	internal := func(uint64) bool { return true }
	ev := g.Gather(testABI, internal, nil)
	if len(ev.Params(testABI)) != 0 {
		t.Fatalf("r0 counted as used before the callee's evidence: %+v", ev)
	}
	callee := &Evidence{IntUsed: []bool{true, false, false, false}, IntSize: []int{4, 0, 0, 0}}
	if !ev.PassThrough(func(uint64) *Evidence { return callee }) {
		t.Fatal("pass-through changed nothing")
	}
	if ps := ev.Params(testABI); len(ps) != 1 || ps[0].Reg != r0 {
		t.Errorf("params %+v", ps)
	}
}
