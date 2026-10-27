package sleigh

import (
	"errors"
	"fmt"
	"strings"
)

// Opcode is a P-code operation, numbered as Ghidra's CPUI_* enum.
type Opcode int

const (
	OpCopy           Opcode = 1
	OpLoad           Opcode = 2
	OpStore          Opcode = 3
	OpBranch         Opcode = 4
	OpCBranch        Opcode = 5
	OpBranchInd      Opcode = 6
	OpCall           Opcode = 7
	OpCallInd        Opcode = 8
	OpCallOther      Opcode = 9
	OpReturn         Opcode = 10
	OpIntEqual       Opcode = 11
	OpIntNotEqual    Opcode = 12
	OpIntSLess       Opcode = 13
	OpIntSLessEqual  Opcode = 14
	OpIntLess        Opcode = 15
	OpIntLessEqual   Opcode = 16
	OpIntZExt        Opcode = 17
	OpIntSExt        Opcode = 18
	OpIntAdd         Opcode = 19
	OpIntSub         Opcode = 20
	OpIntCarry       Opcode = 21
	OpIntSCarry      Opcode = 22
	OpIntSBorrow     Opcode = 23
	OpInt2Comp       Opcode = 24
	OpIntNegate      Opcode = 25
	OpIntXor         Opcode = 26
	OpIntAnd         Opcode = 27
	OpIntOr          Opcode = 28
	OpIntLeft        Opcode = 29
	OpIntRight       Opcode = 30
	OpIntSRight      Opcode = 31
	OpIntMult        Opcode = 32
	OpIntDiv         Opcode = 33
	OpIntSDiv        Opcode = 34
	OpIntRem         Opcode = 35
	OpIntSRem        Opcode = 36
	OpBoolNegate     Opcode = 37
	OpBoolXor        Opcode = 38
	OpBoolAnd        Opcode = 39
	OpBoolOr         Opcode = 40
	OpFloatEqual     Opcode = 41
	OpFloatNotEqual  Opcode = 42
	OpFloatLess      Opcode = 43
	OpFloatLessEqual Opcode = 44
	OpFloatNaN       Opcode = 46
	OpFloatAdd       Opcode = 47
	OpFloatDiv       Opcode = 48
	OpFloatMult      Opcode = 49
	OpFloatSub       Opcode = 50
	OpFloatNeg       Opcode = 51
	OpFloatAbs       Opcode = 52
	OpFloatSqrt      Opcode = 53
	OpFloatInt2Float Opcode = 54
	OpFloatFloat2Flt Opcode = 55
	OpFloatTrunc     Opcode = 56
	OpFloatCeil      Opcode = 57
	OpFloatFloor     Opcode = 58
	OpFloatRound     Opcode = 59
	OpMultiEqual     Opcode = 60
	OpIndirect       Opcode = 61
	OpPiece          Opcode = 62
	OpSubpiece       Opcode = 63
	OpCast           Opcode = 64
	OpPtrAdd         Opcode = 65
	OpPtrSub         Opcode = 66
	OpSegmentOp      Opcode = 67
	OpCPoolRef       Opcode = 68
	OpNew            Opcode = 69
	OpInsert         Opcode = 70
	OpZPull          Opcode = 71
	OpPopCount       Opcode = 72
	OpLzCount        Opcode = 73
	OpSPull          Opcode = 74
	opMax            Opcode = 75
)

var opcodeNames = [opMax]string{
	OpCopy: "COPY", OpLoad: "LOAD", OpStore: "STORE", OpBranch: "BRANCH", OpCBranch: "CBRANCH",
	OpBranchInd: "BRANCHIND", OpCall: "CALL", OpCallInd: "CALLIND", OpCallOther: "CALLOTHER",
	OpReturn: "RETURN", OpIntEqual: "INT_EQUAL", OpIntNotEqual: "INT_NOTEQUAL",
	OpIntSLess: "INT_SLESS", OpIntSLessEqual: "INT_SLESSEQUAL", OpIntLess: "INT_LESS",
	OpIntLessEqual: "INT_LESSEQUAL", OpIntZExt: "INT_ZEXT", OpIntSExt: "INT_SEXT",
	OpIntAdd: "INT_ADD", OpIntSub: "INT_SUB", OpIntCarry: "INT_CARRY", OpIntSCarry: "INT_SCARRY",
	OpIntSBorrow: "INT_SBORROW", OpInt2Comp: "INT_2COMP", OpIntNegate: "INT_NEGATE",
	OpIntXor: "INT_XOR", OpIntAnd: "INT_AND", OpIntOr: "INT_OR", OpIntLeft: "INT_LEFT",
	OpIntRight: "INT_RIGHT", OpIntSRight: "INT_SRIGHT", OpIntMult: "INT_MULT", OpIntDiv: "INT_DIV",
	OpIntSDiv: "INT_SDIV", OpIntRem: "INT_REM", OpIntSRem: "INT_SREM", OpBoolNegate: "BOOL_NEGATE",
	OpBoolXor: "BOOL_XOR", OpBoolAnd: "BOOL_AND", OpBoolOr: "BOOL_OR", OpFloatEqual: "FLOAT_EQUAL",
	OpFloatNotEqual: "FLOAT_NOTEQUAL", OpFloatLess: "FLOAT_LESS", OpFloatLessEqual: "FLOAT_LESSEQUAL",
	OpFloatNaN: "FLOAT_NAN", OpFloatAdd: "FLOAT_ADD", OpFloatDiv: "FLOAT_DIV", OpFloatMult: "FLOAT_MULT",
	OpFloatSub: "FLOAT_SUB", OpFloatNeg: "FLOAT_NEG", OpFloatAbs: "FLOAT_ABS", OpFloatSqrt: "FLOAT_SQRT",
	OpFloatInt2Float: "FLOAT_INT2FLOAT", OpFloatFloat2Flt: "FLOAT_FLOAT2FLOAT",
	OpFloatTrunc: "FLOAT_TRUNC", OpFloatCeil: "FLOAT_CEIL", OpFloatFloor: "FLOAT_FLOOR",
	OpFloatRound: "FLOAT_ROUND", OpMultiEqual: "MULTIEQUAL", OpIndirect: "INDIRECT", OpPiece: "PIECE",
	OpSubpiece: "SUBPIECE", OpCast: "CAST", OpPtrAdd: "PTRADD", OpPtrSub: "PTRSUB",
	OpSegmentOp: "SEGMENTOP", OpCPoolRef: "CPOOLREF", OpNew: "NEW", OpInsert: "INSERT",
	OpZPull: "ZPULL", OpPopCount: "POPCOUNT", OpLzCount: "LZCOUNT", OpSPull: "SPULL",
}

func (o Opcode) String() string {
	if o > 0 && o < opMax && opcodeNames[o] != "" {
		return opcodeNames[o]
	}
	return fmt.Sprintf("OPCODE(%d)", int(o))
}

// Varnode is a sized location: (space, offset, size). In the constant space
// the offset is the value. The first input of LOAD and STORE is a constant
// holding the Index of the space accessed.
type Varnode struct {
	Space  *Space
	Offset uint64
	Size   int
}

func (v Varnode) String() string {
	return fmt.Sprintf("(%s, %#x, %d)", v.Space.Name, v.Offset, v.Size)
}

// PcodeOp is one P-code operation. Relative branches (to another op of the
// same instruction) have a constant first input holding the op-index delta.
type PcodeOp struct {
	Op  Opcode
	Out *Varnode
	In  []Varnode
}

func (op PcodeOp) String() string {
	var b strings.Builder
	if op.Out != nil {
		fmt.Fprintf(&b, "%s = ", op.Out)
	}
	b.WriteString(op.Op.String())
	for i, in := range op.In {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, " %s", in)
	}
	return b.String()
}

// ErrUnimplemented reports an instruction that decodes but whose spec has
// no p-code semantics.
var ErrUnimplemented = errors.New("instruction has no p-code semantics")

// Translate decodes the instruction at addr and returns it with its p-code,
// as Sleigh::oneInstruction does. The length covers any delay slots.
func (d *Decoder) Translate(addr uint64) (*Instruction, []PcodeOp, error) {
	in, c, err := d.decode(addr)
	if err != nil {
		return nil, nil, err
	}
	var ops []PcodeOp
	err = catch(func() {
		fall := c.base.length
		if c.delaySlot > 0 {
			for n := 0; n < c.delaySlot; {
				ds, err := d.resolve(addr + uint64(fall))
				if err != nil {
					badData(&walker{ctx: c}, "delay slot: %v", err)
				}
				fall += ds.base.length
				n += ds.base.length
			}
			c.naddr = addr + uint64(fall)
		}
		b := &builder{dec: d, cache: &pcodeCache{}, uniqMask: d.spec.uniqMask}
		w := &walker{ctx: c}
		w.baseState()
		b.setWalker(w)
		b.build(c.base.ct.templ, -1)
		ops = b.cache.finish(w)
	})
	if errors.Is(err, ErrUnimplemented) {
		return in, nil, fmt.Errorf("%w: %#x: %s", ErrUnimplemented, addr, in)
	}
	if err != nil {
		return nil, nil, err
	}
	return in, ops, nil
}

// unimplemented is panicked when a constructor has no semantics.
type unimplemented struct{}

// pcodeCache collects ops and resolves relative label references once the
// whole instruction is built (Ghidra's PcodeCacher).
type pcodeCache struct {
	ops    []PcodeOp
	labels []int
	refs   []labelRef
}

type labelRef struct {
	op, in int // the op and input holding the label id
	caller int // index of the referencing op
}

func (c *pcodeCache) addLabel(id int) {
	for len(c.labels) <= id {
		c.labels = append(c.labels, -1)
	}
	c.labels[id] = len(c.ops)
}

func (c *pcodeCache) finish(w *walker) []PcodeOp {
	for _, r := range c.refs {
		v := &c.ops[r.op].In[r.in]
		id := int(v.Offset)
		if id >= len(c.labels) || c.labels[id] < 0 {
			badData(w, "reference to undefined p-code label")
		}
		v.Offset = uint64(c.labels[id]-r.caller) & sizeMask(v.Size)
	}
	return c.ops
}

func sizeMask(size int) uint64 {
	if size >= 8 {
		return ^uint64(0)
	}
	return 1<<(8*size) - 1
}

// builder expands constructor templates into p-code (Ghidra's
// SleighBuilder and PcodeBuilder).
type builder struct {
	dec        *Decoder
	cache      *pcodeCache
	w          *walker
	uniqMask   uint64
	uniqOffset uint64
	labelBase  int
	labelCount int
}

func (b *builder) setWalker(w *walker) {
	b.w = w
	b.uniqOffset = (w.addr() & b.uniqMask) << 8
}

func (b *builder) build(t *constructTpl, section int) {
	if t == nil {
		panic(unimplemented{})
	}
	oldBase := b.labelBase
	b.labelBase = b.labelCount
	b.labelCount += t.numLabels
	for _, op := range t.ops {
		switch op.code {
		case opBuild:
			b.appendBuild(op, section)
		case opDelaySlot:
			b.delaySlot()
		case opLabelBuild:
			b.cache.addLabel(int(op.in[0].offset.real) + b.labelBase)
		case opCrossBuild:
			b.appendCrossBuild(op, section)
		default:
			b.dump(op)
		}
	}
	b.labelBase = oldBase
}

// buildSection builds a constructor's main template (section < 0) or a
// named section, recursing into operands when the section is absent.
func (b *builder) buildSection(ct *constructor, section int) {
	if section < 0 {
		b.build(ct.templ, -1)
		return
	}
	if section < len(ct.named) && ct.named[section] != nil {
		b.build(ct.named[section], section)
		return
	}
	for i, op := range ct.operands {
		if _, ok := op.triple.(*subtableSym); !ok {
			continue
		}
		b.w.pushOperand(i)
		b.buildSection(b.w.point.ct, section)
		b.w.popOperand()
	}
}

func (b *builder) appendBuild(op *opTpl, section int) {
	i := int(op.in[0].offset.real)
	if _, ok := b.w.point.ct.operands[i].triple.(*subtableSym); !ok {
		return
	}
	b.w.pushOperand(i)
	b.buildSection(b.w.point.ct, section)
	b.w.popOperand()
}

func (b *builder) delaySlot() {
	saved, savedUniq := b.w, b.uniqOffset
	base := saved.addr()
	fall := saved.ctx.base.length
	for n := 0; n < saved.ctx.delaySlot; {
		c, err := b.dec.resolve(base + uint64(fall))
		if err != nil {
			badData(saved, "delay slot: %v", err)
		}
		c.resolveHandles()
		w := &walker{ctx: c}
		w.baseState()
		b.setWalker(w)
		b.buildSection(c.base.ct, -1)
		fall += c.base.length
		n += c.base.length
	}
	b.w, b.uniqOffset = saved, savedUniq
}

func (b *builder) appendCrossBuild(op *opTpl, section int) {
	if section >= 0 {
		badData(b.w, "crossbuild inside a named section")
	}
	section = int(op.in[1].offset.real)
	vn := op.in[0]
	sp := vn.space.fixSpace(b.w)
	addr := sp.wrap(vn.offset.fix(b.w))
	saved, savedUniq := b.w, b.uniqOffset
	c, err := b.dec.resolve(addr)
	if err != nil {
		badData(saved, "crossbuild: %v", err)
	}
	c.resolveHandles()
	w := &walker{ctx: c, cross: saved.ctx}
	w.baseState()
	b.w, b.uniqOffset = w, (addr&b.uniqMask)<<8
	b.buildSection(c.base.ct, section)
	b.w, b.uniqOffset = saved, savedUniq
}

func (b *builder) location(t *varnodeTpl) Varnode {
	sp := t.space.fixSpace(b.w)
	v := Varnode{Space: sp, Size: int(t.size.fix(b.w))}
	off := t.offset.fix(b.w)
	switch sp.Kind {
	case SpaceConstant:
		v.Offset = off & sizeMask(v.Size)
	case SpaceUnique:
		v.Offset = off | b.uniqOffset
	default:
		v.Offset = sp.wrap(off)
	}
	return v
}

// pointer returns the varnode holding a dynamic handle's address, and the
// space it points into.
func (b *builder) pointer(t *varnodeTpl) (Varnode, *Space) {
	h := &b.w.point.resolve[t.offset.handle].hand
	v := Varnode{Space: h.offsetSpace, Size: h.offsetSize}
	switch h.offsetSpace.Kind {
	case SpaceConstant:
		v.Offset = h.offsetOffset & sizeMask(v.Size)
	case SpaceUnique:
		v.Offset = h.offsetOffset | b.uniqOffset
	default:
		v.Offset = h.offsetSpace.wrap(h.offsetOffset)
	}
	return v, h.space
}

func (b *builder) spaceConst(sp *Space) Varnode {
	return Varnode{Space: b.dec.spec.constSpace, Offset: uint64(sp.Index), Size: 8}
}

// pointerAdd emits INT_ADD for a v_offset_plus handle (a truncated
// dynamic varnode) and returns the adjusted pointer.
func (b *builder) pointerAdd(t *varnodeTpl, ptr Varnode) Varnode {
	plus := t.offset.real & 0xffff
	if t.offset.sel != vOffsetPlus || plus == 0 {
		return ptr
	}
	tmp := Varnode{Space: b.dec.spec.uniqueSpace, Offset: 0x100 + b.dec.spec.uniqBase, Size: ptr.Size}
	b.cache.ops = append(b.cache.ops, PcodeOp{
		Op:  OpIntAdd,
		Out: &tmp,
		In:  []Varnode{ptr, {Space: b.dec.spec.constSpace, Offset: plus, Size: ptr.Size}},
	})
	return tmp
}

// dump emits one template op, staging dynamic inputs through LOAD and a
// dynamic output through STORE.
func (b *builder) dump(t *opTpl) {
	in := make([]Varnode, len(t.in))
	for i, vt := range t.in {
		in[i] = b.location(vt)
		if vt.dynamic(b.w) {
			ptr, sp := b.pointer(vt)
			ptr = b.pointerAdd(vt, ptr)
			out := in[i]
			b.cache.ops = append(b.cache.ops, PcodeOp{Op: OpLoad, Out: &out, In: []Varnode{b.spaceConst(sp), ptr}})
		}
	}
	op := PcodeOp{Op: Opcode(t.code), In: in}
	if len(t.in) > 0 && t.in[0].offset.kind == ctRelative {
		in[0].Offset += uint64(b.labelBase)
		b.cache.refs = append(b.cache.refs, labelRef{op: len(b.cache.ops), in: 0, caller: len(b.cache.ops)})
	}
	var store *PcodeOp
	if t.out != nil {
		out := b.location(t.out)
		op.Out = &out
		if t.out.dynamic(b.w) {
			ptr, sp := b.pointer(t.out)
			store = &PcodeOp{Op: OpStore, In: []Varnode{b.spaceConst(sp), ptr, out}}
		}
	}
	b.cache.ops = append(b.cache.ops, op)
	if store != nil {
		// The INT_ADD for a truncated pointer goes between the op and its
		// STORE, as Ghidra emits it.
		store.In[1] = b.pointerAdd(t.out, store.In[1])
		b.cache.ops = append(b.cache.ops, *store)
	}
}
