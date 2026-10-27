package ssa

import (
	"sort"

	"github.com/stohirov/decompile-anything/internal/ir"
)

// ABI is a calling convention resolved to register varnodes.
type ABI struct {
	SP           ir.Varnode
	IntParams    []ir.Varnode
	FloatParams  []ir.Varnode
	IntReturns   []ir.Varnode
	FloatReturns []ir.Varnode
	// Unaffected registers survive calls; every other register holds an
	// undefined value after one, except the return registers.
	Unaffected  []ir.Varnode
	StackParams bool
	StackOffset int64 // first stack parameter, relative to SP on entry
	StackAlign  int
	ExtraPop    int64 // SP moves this far over a call (the popped return address)
}

// Image is the program memory analysis may read.
type Image interface {
	// ReadOnly returns the size-byte value at addr when all of it lies in
	// memory nothing writes at run time.
	ReadOnly(addr uint64, size int) (uint64, bool)
	// AddressAt reports whether a relocation in [addr, addr+size) refers
	// to the memory around x, so x, read or decoded there, is an address.
	AddressAt(addr uint64, size int, x uint64) bool
}

// Call describes a call value. Before prototype analysis its Args are the
// target (for CALLIND), then the value of every register in Regs, then the
// stack pointer as the callee sees it on entry.
type Call struct {
	Regs []ir.Varnode
	// NArgs counts the bound arguments once prototype analysis has replaced
	// the candidates; -1 before.
	NArgs int
	// Tail marks a jump to another function, which returns for this one.
	Tail bool
	// Proto is the prototype the call was bound with.
	Proto *Proto
	// guessed marks the candidate positions an unknown callee takes.
	guessed map[int]bool
}

// noEffect lists user ops without outputs that change nothing the
// decompiler models: mode switches, barriers, bus locks and exclusive
// monitor marks. They are dropped.
var noEffect = map[string]bool{
	"setISAMode": true, "DataMemoryBarrier": true, "DataSynchronizationBarrier": true,
	"InstructionSynchronizationBarrier": true, "LOCK": true, "UNLOCK": true, "ExclusiveAccess": true,
	"ClearExclusiveLocal": true,
}

// fixedResult gives exclusive-monitor queries the answers they have when
// no other agent touches the location: a load/store-exclusive pair always
// succeeds, so an atomic retry loop runs once. The C output is a plain
// read-modify-write.
var fixedResult = map[string]uint64{
	"hasExclusiveAccess": 1, "ExclusiveMonitorPass": 1, "ExclusiveMonitorsStatus": 0,
}

// Build translates fn's IR CFG into SSA, renaming registers and
// temporaries. Calls get every possible argument register; prototype
// analysis trims them later.
func Build(fn *ir.Function, arch *ir.Arch, abi *ABI, img Image) *Func {
	f := &Func{Name: fn.Name, Entry: fn.Entry, Arch: arch}
	f.Warnings = append(f.Warnings, fn.Warnings...)
	bd := &builder{f: f, arch: arch, abi: abi, img: img, blocks: map[*ir.Block]*Block{}, tables: map[uint64][]ir.JumpCase{}}
	for _, jt := range fn.JumpTables {
		bd.tables[jt.Addr] = jt.Cases
	}
	bd.partition(fn)
	for _, b := range fn.Blocks {
		nb := f.NewBlock(BlockPlain)
		nb.Start = b.Start
		bd.blocks[b] = nb
	}
	insnAt := map[uint64]*ir.Insn{}
	f.insns = map[uint64]int{}
	for _, in := range fn.Insns {
		insnAt[in.Addr] = in
		f.insns[in.Addr] = in.Length
	}
	bd.insnAt = insnAt
	for _, b := range fn.Blocks {
		bd.block(b)
	}
	f.rename()
	return f
}

type builder struct {
	f      *Func
	arch   *ir.Arch
	abi    *ABI
	img    Image
	blocks map[*ir.Block]*Block
	insnAt map[uint64]*ir.Insn
	// vars holds the storage atoms of each space, sorted by offset.
	vars   map[ir.SpaceID][]*Var
	insn   *ir.Insn // the instruction being translated
	tables map[uint64][]ir.JumpCase
}

// partition splits the registers and temporaries fn touches into atoms.
func (bd *builder) partition(fn *ir.Function) {
	ranges := map[ir.SpaceID][][2]int64{}
	add := func(v ir.Varnode) {
		if v.Space == ir.SpaceRegister || v.Space == ir.SpaceUnique {
			ranges[v.Space] = append(ranges[v.Space], [2]int64{int64(v.Offset), int64(v.Offset) + int64(v.Size)})
		}
	}
	for _, b := range fn.Blocks {
		for _, op := range b.Ops {
			if op.Out != nil {
				add(*op.Out)
			}
			for _, in := range op.In {
				add(in)
			}
		}
	}
	add(bd.abi.SP)
	for _, l := range [][]ir.Varnode{bd.abi.IntParams, bd.abi.FloatParams, bd.abi.IntReturns, bd.abi.FloatReturns} {
		for _, v := range l {
			add(v)
		}
	}
	bd.vars = map[ir.SpaceID][]*Var{}
	for space, rs := range ranges {
		bd.vars[space] = atomize(space, rs, func(off int64, size int) string {
			if space == ir.SpaceRegister && bd.arch != nil && bd.arch.Register != nil {
				return bd.arch.Register(uint64(off), uint8(size))
			}
			return ""
		})
	}
	if sp := bd.atoms(bd.abi.SP); len(sp) == 1 {
		bd.f.SP = sp[0]
	}
}

// atomize turns the byte ranges a function accesses in one space into
// variables: overlapping accesses join one variable, and variables wider
// than eight bytes split at 8-byte boundaries so every atom fits a
// machine integer.
func atomize(space ir.SpaceID, rs [][2]int64, name func(off int64, size int) string) []*Var {
	sort.Slice(rs, func(i, j int) bool { return rs[i][0] < rs[j][0] })
	var out []*Var
	for i := 0; i < len(rs); {
		lo, hi := rs[i][0], rs[i][1]
		j := i + 1
		for j < len(rs) && rs[j][0] < hi {
			hi = max(hi, rs[j][1])
			j++
		}
		i = j
		for a := lo; a < hi; {
			end := hi
			if hi-lo > 8 {
				end = min(hi, (a+8)&^7)
			}
			out = append(out, &Var{Space: space, Offset: a, Size: int(end - a), Name: name(a, int(end-a))})
			a = end
		}
	}
	return out
}

// atoms returns the atoms overlapping v.
func (bd *builder) atoms(v ir.Varnode) []*Var {
	all := bd.vars[v.Space]
	lo, hi := int64(v.Offset), int64(v.Offset)+int64(v.Size)
	i := sort.Search(len(all), func(i int) bool { return all[i].Offset+int64(all[i].Size) > lo })
	var out []*Var
	for ; i < len(all) && all[i].Offset < hi; i++ {
		out = append(out, all[i])
	}
	return out
}

// lanes splits a varnode into pieces of at most eight bytes, least
// significant first.
func (bd *builder) lanes(v ir.Varnode) []ir.Varnode {
	if v.Size <= 8 {
		return []ir.Varnode{v}
	}
	var out []ir.Varnode
	for i := 0; i < int(v.Size); i += 8 {
		n := min(8, int(v.Size)-i)
		off := v.Offset + uint64(i)
		if bd.arch.BigEndian {
			off = v.Offset + uint64(int(v.Size)-i-n)
		}
		out = append(out, ir.Varnode{Space: v.Space, Offset: off, Size: uint8(n)})
	}
	return out
}

func (bd *builder) newValue(b *Block, op Op, size int, origin uint64, args ...*Value) *Value {
	return bd.f.NewValue(b, op, size, origin, args...)
}

func (bd *builder) konst(x uint64, size int) *Value {
	if in := bd.insn; in != nil && bd.img != nil && size >= 4 && bd.img.AddressAt(in.Addr, max(in.Length, 1), x) {
		return bd.f.AddrConst(x, size)
	}
	return bd.f.Const(x, size)
}

// read returns the value of a varnode of at most eight bytes.
func (bd *builder) read(b *Block, v ir.Varnode, origin uint64) *Value {
	switch v.Space {
	case ir.SpaceConst:
		return bd.konst(v.Offset, int(v.Size))
	case ir.SpaceRAM:
		ld := bd.newValue(b, ir.OpLoad, int(v.Size), origin, bd.konst(v.Offset, bd.ptrSize()))
		ld.Aux = uint64(ir.SpaceRAM)
		return ld
	}
	lo, hi := int64(v.Offset), int64(v.Offset)+int64(v.Size)
	var result *Value
	for _, a := range bd.atoms(v) {
		r := bd.newValue(b, OpRead, a.Size, origin)
		r.Var = a
		olo, ohi := max(lo, a.Offset), min(hi, a.Offset+int64(a.Size))
		if olo == a.Offset && ohi == a.Offset+int64(a.Size) && olo == lo && ohi == hi {
			return r
		}
		part := bd.sub(b, r, bd.shiftIn(a.Offset, int64(a.Size), olo, ohi), int(ohi-olo), origin)
		if part.Size < int(v.Size) {
			part = bd.newValue(b, ir.OpIntZExt, int(v.Size), origin, part)
		}
		if sh := bd.shiftIn(lo, hi-lo, olo, ohi); sh != 0 {
			part = bd.newValue(b, ir.OpIntLeft, int(v.Size), origin, part, bd.f.Const(uint64(8*sh), 4))
		}
		if result == nil {
			result = part
		} else {
			result = bd.newValue(b, ir.OpIntOr, int(v.Size), origin, result, part)
		}
	}
	if result == nil {
		// Never accessed elsewhere: an unconstrained input.
		return bd.newValue(b, OpUndef, int(v.Size), origin)
	}
	return result
}

// shiftIn returns how many bytes above the least significant end of the
// range [start, start+size) the piece [lo, hi) sits.
func (bd *builder) shiftIn(start, size, lo, hi int64) int64 {
	if bd.arch.BigEndian {
		return start + size - hi
	}
	return lo - start
}

// sub returns size bytes of x starting shift bytes above its least
// significant end.
func (bd *builder) sub(b *Block, x *Value, shift int64, size int, origin uint64) *Value {
	if shift == 0 && size == x.Size {
		return x
	}
	return bd.newValue(b, ir.OpSubpiece, size, origin, x, bd.f.Const(uint64(shift), 4))
}

// write assigns x to a varnode of at most eight bytes.
func (bd *builder) write(b *Block, v ir.Varnode, x *Value, origin uint64) {
	switch v.Space {
	case ir.SpaceRAM:
		bd.newValue(b, ir.OpStore, 0, origin, bd.konst(v.Offset, bd.ptrSize()), x).Aux = uint64(ir.SpaceRAM)
		return
	case ir.SpaceConst:
		bd.f.warn(origin, "write to a constant")
		return
	}
	lo, hi := int64(v.Offset), int64(v.Offset)+int64(v.Size)
	for _, a := range bd.atoms(v) {
		olo, ohi := max(lo, a.Offset), min(hi, a.Offset+int64(a.Size))
		part := bd.sub(b, x, bd.shiftIn(lo, hi-lo, olo, ohi), int(ohi-olo), origin)
		val := part
		if part.Size < a.Size {
			old := bd.newValue(b, OpRead, a.Size, origin)
			old.Var = a
			sh := uint64(8 * bd.shiftIn(a.Offset, int64(a.Size), olo, ohi))
			keep := ^(ir.Mask(part.Size) << sh) & ir.Mask(a.Size)
			val = bd.newValue(b, ir.OpIntZExt, a.Size, origin, part)
			if sh != 0 {
				val = bd.newValue(b, ir.OpIntLeft, a.Size, origin, val, bd.f.Const(sh, 4))
			}
			masked := bd.newValue(b, ir.OpIntAnd, a.Size, origin, old, bd.f.Const(keep, a.Size))
			val = bd.newValue(b, ir.OpIntOr, a.Size, origin, masked, val)
		}
		w := bd.newValue(b, OpWrite, 0, origin, val)
		w.Var = a
	}
}

func (bd *builder) ptrSize() int {
	if bd.arch != nil && bd.arch.PointerSize > 0 {
		return bd.arch.PointerSize
	}
	return 4
}

func (bd *builder) readLanes(b *Block, v ir.Varnode, origin uint64) []*Value {
	if v.Space == ir.SpaceConst && v.Size > 8 {
		out := []*Value{bd.konst(v.Offset, 8)}
		for i := 8; i < int(v.Size); i += 8 {
			out = append(out, bd.f.Const(0, min(8, int(v.Size)-i)))
		}
		return out
	}
	var out []*Value
	for _, l := range bd.lanes(v) {
		out = append(out, bd.read(b, l, origin))
	}
	return out
}

func (bd *builder) writeLanes(b *Block, v ir.Varnode, xs []*Value, origin uint64) {
	for i, l := range bd.lanes(v) {
		bd.write(b, l, xs[i], origin)
	}
}

// block translates one IR block.
func (bd *builder) block(ib *ir.Block) {
	b := bd.blocks[ib]
	for _, s := range ib.Succ {
		ns := bd.blocks[s]
		b.Succs = append(b.Succs, ns)
		ns.Preds = append(ns.Preds, b)
	}
	if len(ib.Ops) > 0 {
		b.End = ib.Ops[len(ib.Ops)-1].Origin
	}
	for i, op := range ib.Ops {
		bd.insn = bd.insnAt[op.Origin]
		if i < len(ib.Ops)-1 || !isTerminator(op.Code) {
			bd.op(b, op)
			continue
		}
		bd.terminator(b, ib, op)
	}
	if len(ib.Ops) == 0 || !isTerminator(ib.Ops[len(ib.Ops)-1].Code) {
		if len(b.Succs) == 1 {
			b.Kind = BlockPlain
		} else {
			b.Kind = BlockStop
		}
	}
	bd.insn = nil
}

func isTerminator(c ir.Opcode) bool {
	switch c {
	case ir.OpBranch, ir.OpCBranch, ir.OpBranchInd, ir.OpReturn:
		return true
	}
	return false
}

func (bd *builder) terminator(b *Block, ib *ir.Block, op ir.Op) {
	switch op.Code {
	case ir.OpBranch:
		if len(b.Succs) == 1 {
			b.Kind = BlockPlain
			return
		}
		if op.In[0].Space != ir.SpaceRAM {
			b.Kind = BlockStop
			bd.f.warn(op.Origin, "relative branch leaves its block")
			return
		}
		bd.tailCall(b, ir.OpCall, nil, op.In[0].Offset, op.Origin)
	case ir.OpCBranch:
		if len(b.Succs) == 2 && b.Succs[0] == b.Succs[1] {
			// Both edges reach the same block: no decision to keep.
			s := b.Succs[0]
			b.Succs = b.Succs[:1]
			for i, p := range s.Preds {
				if p == b {
					s.Preds = append(s.Preds[:i], s.Preds[i+1:]...)
					break
				}
			}
			b.Kind = BlockPlain
			return
		}
		b.Kind = BlockIf
		b.Control = bd.read(b, op.In[1], op.Origin)
	case ir.OpBranchInd:
		target := bd.read(b, op.In[0], op.Origin)
		if len(b.Succs) > 0 {
			b.Kind = BlockSwitch
			b.Control = target
			b.Cases = bd.tables[op.Origin]
			return
		}
		bd.f.warn(op.Origin, "unresolved indirect jump treated as a tail call")
		bd.tailCall(b, ir.OpCallInd, target, 0, op.Origin)
	case ir.OpReturn:
		bd.ret(b, op.Origin)
	}
}

// ret ends b with a return of every return register.
func (bd *builder) ret(b *Block, origin uint64) {
	b.Kind = BlockReturn
	if bd.f.RetRegs == nil {
		bd.f.RetRegs = append(append([]ir.Varnode{}, bd.abi.IntReturns...), bd.abi.FloatReturns...)
	}
	for _, r := range bd.f.RetRegs {
		b.Results = append(b.Results, bd.readReg(b, r, origin))
	}
}

// readWide reads a register of any size, keeping only its low eight bytes
// when wider (vector registers holding a scalar).
func (bd *builder) readWide(b *Block, v ir.Varnode, origin uint64) *Value {
	return bd.readLanes(b, v, origin)[0]
}

// readReg reads an argument or result register. When the register is the
// low part of a wider variable of up to eight bytes (s0 inside d0), it
// reads the whole variable: a double travels in the pair.
func (bd *builder) readReg(b *Block, r ir.Varnode, origin uint64) *Value {
	low := lowBytes(r, 8, bd.arch)
	if as := bd.atoms(low); len(as) == 1 {
		a := as[0]
		lowEnd := a.Offset == int64(low.Offset)
		if bd.arch.BigEndian {
			lowEnd = a.Offset+int64(a.Size) == int64(low.Offset)+int64(low.Size)
		}
		if lowEnd && a.Size > int(low.Size) && a.Size <= 8 {
			return bd.read(b, ir.Varnode{Space: a.Space, Offset: uint64(a.Offset), Size: uint8(a.Size)}, origin)
		}
	}
	return bd.readWide(b, r, origin)
}

func (bd *builder) tailCall(b *Block, code ir.Opcode, target *Value, addr uint64, origin uint64) {
	c := bd.call(b, code, target, addr, origin)
	c.Call.Tail = true
	bd.ret(b, origin)
}

// call emits a call with every candidate argument, then what a call does
// to registers: return registers get the call's results, unaffected
// registers keep their values, the stack pointer moves by the extra pop,
// and everything else becomes undefined.
func (bd *builder) call(b *Block, code ir.Opcode, target *Value, addr uint64, origin uint64) *Value {
	c := bd.newValue(b, code, 0, origin)
	c.Aux = addr
	c.Call = &Call{NArgs: -1}
	if target != nil {
		c.Args = append(c.Args, target)
	}
	for _, l := range [][]ir.Varnode{bd.abi.IntParams, bd.abi.FloatParams} {
		for _, r := range l {
			c.Call.Regs = append(c.Call.Regs, r)
			c.Args = append(c.Args, bd.readReg(b, r, origin))
		}
	}
	sp := bd.read(b, bd.abi.SP, origin)
	c.Args = append(c.Args, sp)

	returns := append(append([]ir.Varnode{}, bd.abi.IntReturns...), bd.abi.FloatReturns...)
	overlaps := func(a *Var, l []ir.Varnode) bool {
		for _, r := range l {
			if r.Space == a.Space && int64(r.Offset) < a.Offset+int64(a.Size) && a.Offset < int64(r.Offset)+int64(r.Size) {
				return true
			}
		}
		return false
	}
	for _, a := range bd.vars[ir.SpaceRegister] {
		var x *Value
		switch {
		case overlaps(a, []ir.Varnode{bd.abi.SP}):
			continue
		case overlaps(a, returns):
			x = bd.newValue(b, OpCallOut, a.Size, origin, c)
			x.Var = a
		case overlaps(a, bd.abi.Unaffected):
			continue
		default:
			x = bd.newValue(b, OpUndef, a.Size, origin)
		}
		w := bd.newValue(b, OpWrite, 0, origin, x)
		w.Var = a
	}
	if bd.abi.ExtraPop != 0 {
		n := int(bd.abi.SP.Size)
		bd.write(b, bd.abi.SP, bd.newValue(b, ir.OpIntAdd, n, origin, sp, bd.f.Const(uint64(bd.abi.ExtraPop), n)), origin)
	}
	return c
}

// op translates one op that does not end its block.
func (bd *builder) op(b *Block, op ir.Op) {
	o := op.Origin
	switch op.Code {
	case ir.OpCall:
		if op.In[0].Space != ir.SpaceRAM {
			bd.f.warn(o, "call to a non-address target")
		}
		bd.call(b, ir.OpCall, nil, op.In[0].Offset, o)
		return
	case ir.OpCallInd:
		bd.call(b, ir.OpCallInd, bd.read(b, op.In[0], o), 0, o)
		return
	case ir.OpCallOther:
		idx := op.In[0].Offset
		if op.Out == nil && bd.arch != nil && int(idx) < len(bd.arch.UserOps) && noEffect[bd.arch.UserOps[idx]] {
			return
		}
		size := 0
		if op.Out != nil {
			size = int(op.Out.Size)
		}
		name := ""
		if bd.arch != nil && int(idx) < len(bd.arch.UserOps) {
			name = bd.arch.UserOps[idx]
		}
		if r, ok := fixedResult[name]; ok && op.Out != nil {
			bd.write(b, *op.Out, bd.f.Const(r, size), o)
			return
		}
		if (name == "VectorSignedToFloat" || name == "VectorUnsignedToFloat") && op.Out != nil && len(op.In) == 3 &&
			op.In[1].Size == op.Out.Size && size <= 8 {
			// VFP's VCVT from an integer register: a scalar conversion
			// (the last operand is the rounding mode).
			x := bd.read(b, op.In[1], o)
			if name == "VectorUnsignedToFloat" {
				x = bd.newValue(b, ir.OpIntZExt, 8, o, x)
			}
			bd.write(b, *op.Out, bd.newValue(b, ir.OpFloatInt2Float, size, o, x), o)
			return
		}
		v := bd.newValue(b, ir.OpCallOther, min(size, 8), o)
		v.Aux = idx
		for _, in := range op.In[1:] {
			v.Args = append(v.Args, bd.readWide(b, in, o))
		}
		if op.Out != nil {
			lanes := []*Value{v}
			for i := 8; i < size; i += 8 {
				lanes = append(lanes, bd.newValue(b, OpUndef, min(8, size-i), o))
			}
			bd.writeLanes(b, *op.Out, lanes, o)
		}
		return
	case ir.OpLoad:
		space := ir.SpaceID(op.In[0].Offset)
		addr := bd.read(b, op.In[1], o)
		if space == ir.SpaceConst {
			bd.write(b, *op.Out, bd.resize(b, addr, int(op.Out.Size), o), o)
			return
		}
		if space != ir.SpaceRAM {
			bd.f.warn(o, "load from the %s space", space)
		}
		var lanes []*Value
		for i, l := range bd.lanes(*op.Out) {
			a := bd.offset(b, addr, bd.laneOffset(*op.Out, i), o)
			lanes = append(lanes, bd.newValue(b, ir.OpLoad, int(l.Size), o, a))
			lanes[i].Aux = uint64(space)
		}
		bd.writeLanes(b, *op.Out, lanes, o)
		return
	case ir.OpStore:
		space := ir.SpaceID(op.In[0].Offset)
		if space != ir.SpaceRAM {
			bd.f.warn(o, "store to the %s space", space)
		}
		addr := bd.read(b, op.In[1], o)
		vals := bd.readLanes(b, op.In[2], o)
		for i := range vals {
			a := bd.offset(b, addr, bd.laneOffset(op.In[2], i), o)
			bd.newValue(b, ir.OpStore, 0, o, a, vals[i]).Aux = uint64(space)
		}
		return
	}
	if op.Out == nil {
		bd.f.warn(o, "%s without an output", op.Code)
		return
	}
	wide := op.Out.Size > 8
	for _, in := range op.In {
		wide = wide || in.Size > 8
	}
	if !wide {
		args := make([]*Value, len(op.In))
		for i, in := range op.In {
			args[i] = bd.read(b, in, o)
		}
		bd.write(b, *op.Out, bd.newValue(b, op.Code, int(op.Out.Size), o, args...), o)
		return
	}
	bd.wideOp(b, op)
}

// laneOffset is the byte offset in memory of lane i of v.
func (bd *builder) laneOffset(v ir.Varnode, i int) int64 {
	n := min(8, int(v.Size)-8*i)
	if bd.arch.BigEndian {
		return int64(int(v.Size) - 8*i - n)
	}
	return int64(8 * i)
}

func (bd *builder) offset(b *Block, addr *Value, off int64, origin uint64) *Value {
	if off == 0 {
		return addr
	}
	return bd.newValue(b, ir.OpIntAdd, addr.Size, origin, addr, bd.f.Const(uint64(off), addr.Size))
}

// resize truncates or zero-extends x to size bytes.
func (bd *builder) resize(b *Block, x *Value, size int, origin uint64) *Value {
	switch {
	case x.Size == size:
		return x
	case x.Size > size:
		return bd.sub(b, x, 0, size, origin)
	}
	return bd.newValue(b, ir.OpIntZExt, size, origin, x)
}

// wideOp translates an op on values wider than eight bytes, lane by lane
// where the op allows it.
func (bd *builder) wideOp(b *Block, op ir.Op) {
	o := op.Origin
	out := *op.Out
	n := len(bd.lanes(out))
	var res []*Value
	switch op.Code {
	case ir.OpCopy, ir.OpIntAnd, ir.OpIntOr, ir.OpIntXor, ir.OpIntNegate:
		ins := make([][]*Value, len(op.In))
		for i, in := range op.In {
			if in.Size != out.Size {
				bd.unsupported(b, op)
				return
			}
			ins[i] = bd.readLanes(b, in, o)
		}
		for l := range n {
			args := make([]*Value, len(ins))
			for i := range ins {
				args[i] = ins[i][l]
			}
			if op.Code == ir.OpCopy {
				res = append(res, args[0])
				continue
			}
			res = append(res, bd.newValue(b, op.Code, args[0].Size, o, args...))
		}
	case ir.OpIntZExt:
		if op.In[0].Size > 8 {
			bd.unsupported(b, op)
			return
		}
		x := bd.read(b, op.In[0], o)
		for l, ln := range bd.lanes(out) {
			if l == 0 {
				res = append(res, bd.resize(b, x, int(ln.Size), o))
			} else {
				res = append(res, bd.f.Const(0, int(ln.Size)))
			}
		}
	case ir.OpSubpiece:
		// Bytes [c, c+size) above the least significant end of the input.
		c := int(op.In[1].Offset)
		if out.Size > 8 || (c%8)+int(out.Size) > 8 {
			bd.unsupported(b, op)
			return
		}
		lanes := bd.readLanes(b, op.In[0], o)
		if c/8 >= len(lanes) {
			bd.unsupported(b, op)
			return
		}
		bd.write(b, out, bd.sub(b, lanes[c/8], int64(c%8), int(out.Size), o), o)
		return
	case ir.OpPiece:
		hi, lo := op.In[0], op.In[1]
		if lo.Size%8 != 0 {
			bd.unsupported(b, op)
			return
		}
		res = append(bd.readLanes(b, lo, o), bd.readLanes(b, hi, o)...)
	default:
		bd.unsupported(b, op)
		return
	}
	bd.writeLanes(b, out, res, o)
}

func (bd *builder) unsupported(b *Block, op ir.Op) {
	bd.f.warn(op.Origin, "%s on values wider than 8 bytes is not supported", op.Code)
	var res []*Value
	for _, l := range bd.lanes(*op.Out) {
		res = append(res, bd.newValue(b, OpUndef, int(l.Size), op.Origin))
	}
	bd.writeLanes(b, *op.Out, res, op.Origin)
}
