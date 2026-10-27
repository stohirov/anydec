package sleigh

// Pattern expressions compute operand values from instruction and context
// bits. All arithmetic is on int64, as Ghidra's intb.

type expr interface {
	value(w *walker) int64
}

func signExtend(v int64, bit int) int64 {
	if bit >= 63 {
		return v
	}
	sa := 63 - bit
	return v << sa >> sa
}

func zeroExtend(v int64, bit int) int64 {
	if bit >= 63 {
		return v
	}
	sa := 63 - bit
	return int64(uint64(v) << sa >> sa)
}

// tokenField is a bit range of an instruction token.
type tokenField struct {
	bigEndian          bool
	signBit            bool
	bitStart, bitEnd   int
	byteStart, byteEnd int
	shift              int
}

func (f *tokenField) value(w *walker) int64 {
	size := f.byteEnd - f.byteStart + 1
	var v int64
	for i := 0; i < size; i++ {
		v = v<<8 | int64(w.instructionByte(f.byteStart+i))
	}
	if !f.bigEndian {
		var r int64
		for i := 0; i < size; i++ {
			r = r<<8 | v&0xff
			v >>= 8
		}
		v = r
	}
	v >>= f.shift
	if f.signBit {
		return signExtend(v, f.bitEnd-f.bitStart)
	}
	return zeroExtend(v, f.bitEnd-f.bitStart)
}

// contextField is a bit range of the context register.
type contextField struct {
	signBit            bool
	startBit, endBit   int
	startByte, endByte int
	shift              int
}

func (f *contextField) value(w *walker) int64 {
	var v int64
	for i := f.startByte; i <= f.endByte; i++ {
		v = v<<8 | int64(w.ctx.contextByte(i))
	}
	v >>= f.shift
	if f.signBit {
		return signExtend(v, f.endBit-f.startBit)
	}
	return zeroExtend(v, f.endBit-f.startBit)
}

type constValue int64

func (c constValue) value(*walker) int64 { return int64(c) }

type startValue struct{}
type endValue struct{}
type next2Value struct{}

func (startValue) value(w *walker) int64 {
	return int64(w.ctx.addr / uint64(w.ctx.spec.DefaultSpace.WordSize))
}
func (endValue) value(w *walker) int64 {
	return int64(w.naddr() / uint64(w.ctx.spec.DefaultSpace.WordSize))
}
func (next2Value) value(w *walker) int64 {
	return int64(w.n2addr() / uint64(w.ctx.spec.DefaultSpace.WordSize))
}

// operandValue is the value of another operand of the same constructor,
// evaluated at that operand's position in the instruction.
type operandValue struct {
	index int
	ct    *constructor
}

func (o *operandValue) value(w *walker) int64 {
	sym := o.ct.operands[o.index]
	e := sym.def
	if e == nil {
		if sym.triple == nil {
			return 0
		}
		if _, ok := sym.triple.(*subtableSym); ok {
			return 0
		}
		e = sym.triple.patternExpr()
	}
	var temp constructState
	nw := walker{ctx: w.ctx}
	if !nw.setOutOfBandState(o.ct, o.index, &temp, w) {
		return 0
	}
	return e.value(&nw)
}

type binaryExpr struct {
	op   uint32
	l, r expr
}

func (b *binaryExpr) value(w *walker) int64 {
	l, r := b.l.value(w), b.r.value(w)
	switch b.op {
	case ePlusExp:
		return l + r
	case eSubExp:
		return l - r
	case eMultExp:
		return l * r
	case eLshiftExp:
		return l << uint64(r)
	case eRshiftExp:
		return l >> uint64(r)
	case eAndExp:
		return l & r
	case eOrExp:
		return l | r
	case eXorExp:
		return l ^ r
	case eDivExp:
		if r == 0 {
			badData(w, "division by zero in pattern expression")
		}
		return l / r
	}
	panic("sleigh: unknown binary expression")
}

type unaryExpr struct {
	op uint32
	x  expr
}

func (u *unaryExpr) value(w *walker) int64 {
	v := u.x.value(w)
	if u.op == eMinusExp {
		return -v
	}
	return ^v
}

// Patterns test fixed bits of the instruction and context.

type disjointPattern interface {
	match(w *walker) bool
}

type instructionPattern struct{ b *patternBlock }
type contextPattern struct{ b *patternBlock }
type combinePattern struct{ context, instr *patternBlock }

func (p instructionPattern) match(w *walker) bool { return p.b.matchInstruction(w) }
func (p contextPattern) match(w *walker) bool     { return p.b.matchContext(w) }
func (p combinePattern) match(w *walker) bool {
	return p.instr.matchInstruction(w) && p.context.matchContext(w)
}

// patternBlock is a mask/value test on 32-bit words starting at a byte
// offset. nonZero is 0 for always-true and negative for always-false.
type patternBlock struct {
	offset    int
	nonZero   int
	mask, val []uint32
}

func (b *patternBlock) matchInstruction(w *walker) bool {
	if b.nonZero <= 0 {
		return b.nonZero == 0
	}
	off := b.offset
	for i, m := range b.mask {
		if m&w.instructionWord(off) != b.val[i] {
			return false
		}
		off += 4
	}
	return true
}

func (b *patternBlock) matchContext(w *walker) bool {
	if b.nonZero <= 0 {
		return b.nonZero == 0
	}
	off := b.offset
	for i, m := range b.mask {
		if m&w.ctx.contextWordAt(off) != b.val[i] {
			return false
		}
		off += 4
	}
	return true
}

// normalize trims zero mask words and bytes, as PatternBlock::normalize
// does, so blocks match exactly what Ghidra matches.
func (b *patternBlock) normalize() {
	if b.nonZero <= 0 {
		b.offset, b.mask, b.val = 0, nil, nil
		return
	}
	for len(b.mask) > 0 && b.mask[0] == 0 {
		b.mask, b.val = b.mask[1:], b.val[1:]
		b.offset += 4
	}
	if len(b.mask) > 0 {
		suboff := 0
		for t := b.mask[0]; t != 0; t >>= 8 {
			suboff++
		}
		suboff = 4 - suboff
		if suboff != 0 {
			b.offset += suboff
			slide := func(v []uint32) {
				for i := 0; i < len(v)-1; i++ {
					v[i] = v[i]<<(suboff*8) | v[i+1]>>((4-suboff)*8)
				}
				v[len(v)-1] <<= suboff * 8
			}
			slide(b.mask)
			slide(b.val)
		}
		n := len(b.mask)
		for n > 0 && b.mask[n-1] == 0 {
			n--
		}
		b.mask, b.val = b.mask[:n], b.val[:n]
	}
	if len(b.mask) == 0 {
		b.offset, b.nonZero = 0, 0
		return
	}
	b.nonZero = len(b.mask) * 4
	for t := b.mask[len(b.mask)-1]; t&0xff == 0; t >>= 8 {
		b.nonZero--
	}
}
