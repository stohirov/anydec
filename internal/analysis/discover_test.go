package analysis

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/loader"
)

// A fake ISA: every instruction is 4 bytes and lifts to whatever ops the
// test gives it.

type fakeLifter map[uint64][]ir.Op

var errFakeBad = errors.New("bad instruction")

func (f fakeLifter) Lift(addr uint64) (*ir.Insn, error) {
	ops, ok := f[addr]
	if !ok {
		return nil, errFakeBad
	}
	out := make([]ir.Op, len(ops))
	for i, op := range ops {
		op.Origin = addr
		out[i] = op
	}
	return &ir.Insn{Addr: addr, Length: 4, Ops: out}, nil
}

var (
	r0   = ir.Varnode{Space: ir.SpaceRegister, Offset: 0, Size: 4}
	r1   = ir.Varnode{Space: ir.SpaceRegister, Offset: 4, Size: 4}
	flag = ir.Varnode{Space: ir.SpaceRegister, Offset: 0x10, Size: 1}
)

func c(v uint64, size uint8) ir.Varnode {
	return ir.Varnode{Space: ir.SpaceConst, Offset: v, Size: size}
}
func ram(a uint64) ir.Varnode { return ir.Varnode{Space: ir.SpaceRAM, Offset: a, Size: 4} }
func op(code ir.Opcode, out *ir.Varnode, in ...ir.Varnode) ir.Op {
	return ir.Op{Code: code, Out: out, In: in}
}
func ret() ir.Op { return op(ir.OpReturn, nil, r1) }

// program maps [0x1000, 0x1100) as code with functions at the given
// entries, and words as initial memory.
func program(entries []uint64, words map[uint64]uint32) *loader.Program {
	data := make([]byte, 0x100)
	for a, w := range words {
		binary.LittleEndian.PutUint32(data[a-0x1000:], w)
	}
	p := &loader.Program{Segments: []loader.Segment{{Name: ".text", Addr: 0x1000, Data: data, Perm: loader.PermR | loader.PermX}}}
	for _, e := range entries {
		p.Symbols = append(p.Symbols, loader.Symbol{Name: "f", Addr: e, Kind: loader.SymFunction})
	}
	return p
}

func discover(t *testing.T, p *loader.Program, l fakeLifter) map[uint64]*ir.Function {
	t.Helper()
	out := map[uint64]*ir.Function{}
	for _, fn := range Discover(p, l, Options{}) {
		if err := fn.Verify(); err != nil {
			t.Fatal(err)
		}
		out[fn.Entry] = fn
	}
	return out
}

func lastOp(b *ir.Block) ir.Opcode { return b.Ops[len(b.Ops)-1].Code }

func TestBranchInsideInstruction(t *testing.T) {
	// A conditional instruction: skip the COPY when flag is set.
	l := fakeLifter{
		0x1000: {op(ir.OpCBranch, nil, c(2, 4), flag), op(ir.OpCopy, &r0, c(1, 4))},
		0x1004: {ret()},
	}
	fn := discover(t, program([]uint64{0x1000}, nil), l)[0x1000]
	if len(fn.Blocks) != 3 {
		t.Fatalf("%d blocks, want 3", len(fn.Blocks))
	}
	entry := fn.Blocks[0]
	if lastOp(entry) != ir.OpCBranch || len(entry.Succ) != 2 {
		t.Fatalf("entry block ends in %s with %d successors", lastOp(entry), len(entry.Succ))
	}
	copyBlock, exit := entry.Succ[0], entry.Succ[1]
	if copyBlock.Ops[0].Code != ir.OpCopy || copyBlock.Start != 0x1000 {
		t.Errorf("fall-through block starts with %s at %#x", copyBlock.Ops[0].Code, copyBlock.Start)
	}
	if lastOp(exit) != ir.OpReturn || exit.Start != 0x1004 || copyBlock.Succ[0] != exit {
		t.Errorf("taken branch does not reach the return")
	}
}

func TestConditionalTailCall(t *testing.T) {
	l := fakeLifter{
		0x1000: {op(ir.OpCBranch, nil, ram(0x1080), flag)},
		0x1004: {ret()},
		0x1080: {ret()},
	}
	fns := discover(t, program([]uint64{0x1000, 0x1080}, nil), l)
	fn := fns[0x1000]
	entry := fn.Blocks[0]
	if len(entry.Succ) != 2 {
		t.Fatalf("CBRANCH block has %d successors", len(entry.Succ))
	}
	stub := entry.Succ[1]
	if len(stub.Ops) != 1 || stub.Ops[0].Code != ir.OpBranch || stub.Ops[0].In[0] != ram(0x1080) || len(stub.Succ) != 0 {
		t.Errorf("taken edge goes to %+v, want a lone BRANCH to 0x1080", stub.Ops)
	}
	if len(fn.Calls) != 1 || fn.Calls[0] != 0x1080 {
		t.Errorf("calls %#x", fn.Calls)
	}
	if len(fn.Insns) != 2 {
		t.Errorf("function absorbed the callee: %d instructions", len(fn.Insns))
	}
}

func TestBranchToInstructionWithoutOps(t *testing.T) {
	l := fakeLifter{
		0x1000: {op(ir.OpBranch, nil, ram(0x1008))},
		0x1008: {}, // a nop
		0x100c: {ret()},
	}
	fn := discover(t, program([]uint64{0x1000}, nil), l)[0x1000]
	if len(fn.Blocks) != 2 || fn.Blocks[0].Succ[0].Start != 0x100c {
		t.Fatalf("blocks %+v", fn.Blocks)
	}
	if len(fn.Insns) != 3 {
		t.Errorf("%d instructions, want the nop included", len(fn.Insns))
	}
}

func TestDiscoversCallTargets(t *testing.T) {
	l := fakeLifter{
		0x1000: {op(ir.OpCall, nil, ram(0x1040))},
		0x1004: {ret()},
		0x1040: {ret()},
	}
	fns := discover(t, program([]uint64{0x1000}, nil), l)
	if fns[0x1040] == nil || fns[0x1040].Name != "sub_1040" {
		t.Fatalf("call target not discovered: %v", fns)
	}
}

func TestResolvesGuardedJumpTable(t *testing.T) {
	// if (r0 > 3) goto 0x1040; goto *table[r0], with the table at 0x1020.
	t1 := ir.Varnode{Space: ir.SpaceUnique, Offset: 0x100, Size: 4}
	l := fakeLifter{
		0x1000: {op(ir.OpIntLess, &flag, c(3, 4), r0), op(ir.OpCBranch, nil, ram(0x1040), flag)},
		0x1004: {
			op(ir.OpIntMult, &t1, r0, c(4, 4)),
			op(ir.OpIntAdd, &t1, t1, c(0x1020, 4)),
			op(ir.OpLoad, &r1, c(uint64(ir.SpaceRAM), 8), t1),
			op(ir.OpBranchInd, nil, r1),
		},
		0x1030: {ret()}, 0x1034: {ret()}, 0x1038: {ret()}, 0x103c: {ret()},
		0x1040: {ret()},
	}
	table := map[uint64]uint32{0x1020: 0x1030, 0x1024: 0x1034, 0x1028: 0x1038, 0x102c: 0x103c}
	// The table must not be writable to be trusted.
	p := program([]uint64{0x1000}, table)
	fn := discover(t, p, l)[0x1000]
	if len(fn.JumpTables) != 1 || len(fn.Unresolved) != 0 {
		t.Fatalf("tables %+v unresolved %#x", fn.JumpTables, fn.Unresolved)
	}
	for i, cs := range fn.JumpTables[0].Cases {
		if cs.Value != int64(i) || cs.Target != 0x1030+4*uint64(i) {
			t.Errorf("case %d = %+v", i, cs)
		}
	}
	var jump *ir.Block
	for _, b := range fn.Blocks {
		if lastOp(b) == ir.OpBranchInd {
			jump = b
		}
	}
	if jump == nil || len(jump.Succ) != 4 {
		t.Fatalf("indirect jump block has %d successors", len(jump.Succ))
	}

	// The same jump from a writable table proves nothing.
	p.Segments[0].Perm |= loader.PermW
	fn = discover(t, p, l)[0x1000]
	if len(fn.JumpTables) != 0 || len(fn.Unresolved) != 1 {
		t.Errorf("writable table: tables %+v unresolved %#x", fn.JumpTables, fn.Unresolved)
	}
}

func TestUnboundedJumpStaysUnresolved(t *testing.T) {
	l := fakeLifter{0x1000: {op(ir.OpBranchInd, nil, r0)}}
	fn := discover(t, program([]uint64{0x1000}, nil), l)[0x1000]
	if len(fn.Unresolved) != 1 || fn.Unresolved[0] != 0x1000 || len(fn.JumpTables) != 0 {
		t.Errorf("tables %+v unresolved %#x", fn.JumpTables, fn.Unresolved)
	}
}

func TestBadInstructionWarns(t *testing.T) {
	l := fakeLifter{0x1000: {op(ir.OpCopy, &r0, c(1, 4))}} // falls into 0x1004, which does not decode
	fn := discover(t, program([]uint64{0x1000}, nil), l)[0x1000]
	if len(fn.Warnings) == 0 || fn.Warnings[0].Addr != 0x1004 {
		t.Errorf("warnings %v", fn.Warnings)
	}
}

func TestResolvesJumpGuardedBeforeMerge(t *testing.T) {
	// ARM's "cmp r0,#3; movhi r0,#0; bxhi lr; ldr pc,[table, r0, lsl #2]":
	// conditional instructions split the guard into blocks that merge
	// before the jump, and r0 is 0 on one of the merging paths.
	t0 := ir.Varnode{Space: ir.SpaceUnique, Offset: 0x200, Size: 1}
	t1 := ir.Varnode{Space: ir.SpaceUnique, Offset: 0x100, Size: 4}
	l := fakeLifter{
		0x1000: {op(ir.OpIntLess, &flag, c(3, 4), r0)},
		0x1004: {op(ir.OpBoolNegate, &t0, flag), op(ir.OpCBranch, nil, c(2, 4), t0), op(ir.OpCopy, &r0, c(0, 4))},
		0x1008: {op(ir.OpBoolNegate, &t0, flag), op(ir.OpCBranch, nil, c(2, 4), t0), ret()},
		0x100c: {
			op(ir.OpIntMult, &t1, r0, c(4, 4)),
			op(ir.OpIntAdd, &t1, t1, c(0x1020, 4)),
			op(ir.OpLoad, &r1, c(uint64(ir.SpaceRAM), 8), t1),
			op(ir.OpBranchInd, nil, r1),
		},
		0x1030: {ret()}, 0x1034: {ret()}, 0x1038: {ret()}, 0x103c: {ret()},
	}
	table := map[uint64]uint32{0x1020: 0x1030, 0x1024: 0x1034, 0x1028: 0x1038, 0x102c: 0x103c}
	fn := discover(t, program([]uint64{0x1000}, table), l)[0x1000]
	if len(fn.JumpTables) != 1 || len(fn.JumpTables[0].Cases) != 4 {
		t.Fatalf("tables %+v unresolved %#x", fn.JumpTables, fn.Unresolved)
	}
	for i, cs := range fn.JumpTables[0].Cases {
		if cs.Value != int64(i) || cs.Target != 0x1030+4*uint64(i) {
			t.Errorf("case %d = %+v", i, cs)
		}
	}
}
