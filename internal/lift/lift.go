// Package lift translates SLEIGH P-code into IR, one op for one op. It is
// the only stage that knows about SLEIGH; everything after it sees IR.
package lift

import (
	"fmt"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/sleigh"
)

// Lifter decodes instructions with a SLEIGH decoder and lifts them to IR.
type Lifter struct {
	dec    *sleigh.Decoder
	arch   *ir.Arch
	spaces []ir.SpaceID // by sleigh space index; spaceNone if unsupported
}

const spaceNone ir.SpaceID = 0xff

// New returns a lifter over dec, whose context (instruction-set modes) the
// caller has set up.
func New(language string, dec *sleigh.Decoder) *Lifter {
	spec := dec.Spec()
	l := &Lifter{dec: dec, spaces: make([]ir.SpaceID, len(spec.Spaces))}
	for i, sp := range spec.Spaces {
		l.spaces[i] = spaceNone
		switch {
		case sp == nil:
		case sp.Kind == sleigh.SpaceConstant:
			l.spaces[i] = ir.SpaceConst
		case sp.Kind == sleigh.SpaceUnique:
			l.spaces[i] = ir.SpaceUnique
		case sp == spec.DefaultSpace:
			l.spaces[i] = ir.SpaceRAM
		case sp.Kind == sleigh.SpaceProcessor && sp.Name == "register":
			l.spaces[i] = ir.SpaceRegister
		}
	}
	regs := spec.Space("register")
	l.arch = &ir.Arch{
		Language:    language,
		BigEndian:   spec.BigEndian,
		PointerSize: spec.DefaultSpace.Size,
		UserOps:     spec.UserOps(),
		Register: func(off uint64, size uint8) string {
			if regs == nil {
				return ""
			}
			return spec.RegisterName(regs, off, int(size))
		},
	}
	return l
}

// Arch describes the processor the lifter's IR comes from.
func (l *Lifter) Arch() *ir.Arch { return l.arch }

// Register returns the varnode of the named register, or false.
func (l *Lifter) Register(name string) (ir.Varnode, bool) {
	r := l.dec.Spec().Register(name)
	if r == nil || l.spaces[r.Space.Index] != ir.SpaceRegister || r.Size > 255 {
		return ir.Varnode{}, false
	}
	return ir.Varnode{Space: ir.SpaceRegister, Offset: r.Offset, Size: uint8(r.Size)}, true
}

// Lift decodes the instruction at addr and lifts its P-code. An instruction
// that decodes but has no semantics in the spec comes back with no ops and
// an error wrapping sleigh.ErrUnimplemented.
func (l *Lifter) Lift(addr uint64) (*ir.Insn, error) {
	in, ops, err := l.dec.Translate(addr)
	if in == nil {
		return nil, err
	}
	// The ops include those of delay-slot instructions, so the IR
	// instruction spans them too.
	insn := &ir.Insn{Addr: in.Addr, Length: in.Length + in.DelaySlot, Bytes: in.Bytes, Text: in.String()}
	if err != nil {
		return insn, err
	}
	insn.Ops = make([]ir.Op, len(ops))
	for i, op := range ops {
		o, err := l.op(op, addr)
		if err != nil {
			return insn, fmt.Errorf("lift %#x (%s): %w", addr, insn.Text, err)
		}
		insn.Ops[i] = o
	}
	return insn, nil
}

func (l *Lifter) op(op sleigh.PcodeOp, origin uint64) (ir.Op, error) {
	code, ok := opcodes[op.Op]
	if !ok {
		return ir.Op{}, fmt.Errorf("p-code %s has no IR opcode", op.Op)
	}
	o := ir.Op{Code: code, Origin: origin, In: make([]ir.Varnode, len(op.In))}
	if op.Out != nil {
		v, err := l.varnode(*op.Out)
		if err != nil {
			return ir.Op{}, err
		}
		o.Out = &v
	}
	for i, in := range op.In {
		v, err := l.varnode(in)
		if err != nil {
			return ir.Op{}, err
		}
		if i == 0 && (code == ir.OpLoad || code == ir.OpStore) {
			// The space operand holds a sleigh space index; make it an IR one.
			if in.Offset >= uint64(len(l.spaces)) || l.spaces[in.Offset] == spaceNone {
				return ir.Op{}, fmt.Errorf("%s from unsupported space %d", op.Op, in.Offset)
			}
			v.Offset = uint64(l.spaces[in.Offset])
		}
		o.In[i] = v
	}
	return o, nil
}

func (l *Lifter) varnode(v sleigh.Varnode) (ir.Varnode, error) {
	if v.Space == nil || v.Space.Index >= len(l.spaces) || l.spaces[v.Space.Index] == spaceNone {
		name := "<nil>"
		if v.Space != nil {
			name = v.Space.Name
		}
		return ir.Varnode{}, fmt.Errorf("varnode in unsupported space %s", name)
	}
	if v.Size <= 0 || v.Size > 255 {
		return ir.Varnode{}, fmt.Errorf("%d-byte varnode", v.Size)
	}
	return ir.Varnode{Space: l.spaces[v.Space.Index], Offset: v.Offset, Size: uint8(v.Size)}, nil
}

var opcodes = map[sleigh.Opcode]ir.Opcode{
	sleigh.OpCopy: ir.OpCopy, sleigh.OpLoad: ir.OpLoad, sleigh.OpStore: ir.OpStore,
	sleigh.OpBranch: ir.OpBranch, sleigh.OpCBranch: ir.OpCBranch, sleigh.OpBranchInd: ir.OpBranchInd,
	sleigh.OpCall: ir.OpCall, sleigh.OpCallInd: ir.OpCallInd, sleigh.OpCallOther: ir.OpCallOther,
	sleigh.OpReturn:   ir.OpReturn,
	sleigh.OpIntEqual: ir.OpIntEqual, sleigh.OpIntNotEqual: ir.OpIntNotEqual,
	sleigh.OpIntSLess: ir.OpIntSLess, sleigh.OpIntSLessEqual: ir.OpIntSLessEqual,
	sleigh.OpIntLess: ir.OpIntLess, sleigh.OpIntLessEqual: ir.OpIntLessEqual,
	sleigh.OpIntZExt: ir.OpIntZExt, sleigh.OpIntSExt: ir.OpIntSExt,
	sleigh.OpIntAdd: ir.OpIntAdd, sleigh.OpIntSub: ir.OpIntSub,
	sleigh.OpIntCarry: ir.OpIntCarry, sleigh.OpIntSCarry: ir.OpIntSCarry, sleigh.OpIntSBorrow: ir.OpIntSBorrow,
	sleigh.OpInt2Comp: ir.OpInt2Comp, sleigh.OpIntNegate: ir.OpIntNegate,
	sleigh.OpIntXor: ir.OpIntXor, sleigh.OpIntAnd: ir.OpIntAnd, sleigh.OpIntOr: ir.OpIntOr,
	sleigh.OpIntLeft: ir.OpIntLeft, sleigh.OpIntRight: ir.OpIntRight, sleigh.OpIntSRight: ir.OpIntSRight,
	sleigh.OpIntMult: ir.OpIntMult, sleigh.OpIntDiv: ir.OpIntDiv, sleigh.OpIntSDiv: ir.OpIntSDiv,
	sleigh.OpIntRem: ir.OpIntRem, sleigh.OpIntSRem: ir.OpIntSRem,
	sleigh.OpBoolNegate: ir.OpBoolNegate, sleigh.OpBoolXor: ir.OpBoolXor,
	sleigh.OpBoolAnd: ir.OpBoolAnd, sleigh.OpBoolOr: ir.OpBoolOr,
	sleigh.OpFloatEqual: ir.OpFloatEqual, sleigh.OpFloatNotEqual: ir.OpFloatNotEqual,
	sleigh.OpFloatLess: ir.OpFloatLess, sleigh.OpFloatLessEqual: ir.OpFloatLessEqual,
	sleigh.OpFloatNaN: ir.OpFloatNaN, sleigh.OpFloatAdd: ir.OpFloatAdd, sleigh.OpFloatDiv: ir.OpFloatDiv,
	sleigh.OpFloatMult: ir.OpFloatMult, sleigh.OpFloatSub: ir.OpFloatSub, sleigh.OpFloatNeg: ir.OpFloatNeg,
	sleigh.OpFloatAbs: ir.OpFloatAbs, sleigh.OpFloatSqrt: ir.OpFloatSqrt,
	sleigh.OpFloatInt2Float: ir.OpFloatInt2Float, sleigh.OpFloatFloat2Flt: ir.OpFloatFloat2Float,
	sleigh.OpFloatTrunc: ir.OpFloatTrunc, sleigh.OpFloatCeil: ir.OpFloatCeil,
	sleigh.OpFloatFloor: ir.OpFloatFloor, sleigh.OpFloatRound: ir.OpFloatRound,
	sleigh.OpMultiEqual: ir.OpPhi, sleigh.OpIndirect: ir.OpIndirect,
	sleigh.OpPiece: ir.OpPiece, sleigh.OpSubpiece: ir.OpSubpiece, sleigh.OpCast: ir.OpCast,
	sleigh.OpPtrAdd: ir.OpPtrAdd, sleigh.OpPtrSub: ir.OpPtrSub, sleigh.OpSegmentOp: ir.OpSegmentOp,
	sleigh.OpCPoolRef: ir.OpCPoolRef, sleigh.OpNew: ir.OpNew, sleigh.OpInsert: ir.OpInsert,
	sleigh.OpPopCount: ir.OpPopCount, sleigh.OpLzCount: ir.OpLzCount,
}
