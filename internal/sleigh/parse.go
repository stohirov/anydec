package sleigh

import "fmt"

// Limits from Ghidra's ParserContext.
const (
	maxDepth   = 32
	maxOperand = 20
	maxInsnLen = 16
)

// handle is a resolved varnode: Ghidra's FixedHandle. When offsetSpace is
// set the varnode is dynamic: it lives at a pointer stored in
// (offsetSpace, offsetOffset, offsetSize), and its value is staged in the
// temporary (tempSpace, tempOffset).
type handle struct {
	space        *Space
	size         int
	offsetSpace  *Space
	offsetOffset uint64
	offsetSize   int
	tempSpace    *Space
	tempOffset   uint64
}

// constructState is one node of the tree of matched constructors.
type constructState struct {
	ct      *constructor
	hand    handle
	resolve [maxOperand]*constructState
	parent  *constructState
	length  int
	offset  int // from the start of the instruction
}

// contextSet is a pending globalset, applied once the instruction is
// complete.
type contextSet struct {
	sym   tripleSymbol
	point *constructState
	num   int
	mask  uint32
	value uint32
	flow  bool
}

// parserContext holds one instruction's decoding state.
type parserContext struct {
	spec      *Spec
	dec       *Decoder
	buf       [maxInsnLen + 8]byte // zero padding past the instruction window
	context   []uint32
	commits   []contextSet
	addr      uint64
	naddr     uint64
	next2     uint64
	haveNext2 bool
	base      *constructState
	delaySlot int
}

func (c *parserContext) n2addr() uint64 {
	if !c.haveNext2 {
		next, err := c.dec.resolve(c.naddr)
		if err != nil {
			panic(badDataError{fmt.Sprintf("inst_next2 at %#x: %v", c.naddr, err)})
		}
		c.next2, c.haveNext2 = next.naddr, true
	}
	return c.next2
}

func (c *parserContext) setContextWord(i int, val, mask uint32) {
	c.context[i] = c.context[i]&^mask | val&mask
}

func (c *parserContext) contextWord(i int) uint32 {
	if i < 0 || i >= len(c.context) {
		return 0
	}
	return c.context[i]
}

// contextByte returns byte i of the context, most significant byte of word
// 0 first.
func (c *parserContext) contextByte(i int) byte {
	return byte(c.contextWord(i/4) >> (8 * (3 - i%4)))
}

// contextWordAt returns the 4 context bytes starting at byte offset off.
func (c *parserContext) contextWordAt(off int) uint32 {
	v := uint64(c.contextWord(off/4))<<32 | uint64(c.contextWord(off/4+1))
	return uint32(v >> (32 - 8*(off%4)))
}

// walker traverses a parserContext's constructor tree; Ghidra's
// ParserWalker and ParserWalkerChange in one.
type walker struct {
	ctx        *parserContext
	cross      *parserContext // for crossbuild: the instruction whose addresses apply
	point      *constructState
	depth      int
	breadcrumb [maxDepth]int
}

func (w *walker) addr() uint64 {
	if w.cross != nil {
		return w.cross.addr
	}
	return w.ctx.addr
}

func (w *walker) naddr() uint64 {
	if w.cross != nil {
		return w.cross.naddr
	}
	return w.ctx.naddr
}

func (w *walker) n2addr() uint64 {
	if w.cross != nil {
		return w.cross.n2addr()
	}
	return w.ctx.n2addr()
}

func (w *walker) baseState() {
	w.point, w.depth, w.breadcrumb[0] = w.ctx.base, 0, 0
}

func (w *walker) pushOperand(i int) {
	if w.depth > maxDepth-2 {
		badData(w, "exceeded maximum parse depth")
	}
	w.breadcrumb[w.depth] = i + 1
	w.depth++
	w.point = w.point.resolve[i]
	w.breadcrumb[w.depth] = 0
}

func (w *walker) popOperand() {
	w.point = w.point.parent
	w.depth--
}

func (w *walker) operand() int { return w.breadcrumb[w.depth] }

// offset returns the byte offset of operand i's end, or of the current
// constructor when i < 0.
func (w *walker) offset(i int) int {
	if i < 0 {
		return w.point.offset
	}
	op := w.point.resolve[i]
	return op.offset + op.length
}

// allocateOperand descends into a new child node for operand i.
func (w *walker) allocateOperand(i int) {
	if i >= maxOperand {
		badData(w, "constructor has too many operands")
	}
	if w.depth > maxDepth-2 {
		badData(w, "exceeded maximum parse depth")
	}
	st := &constructState{parent: w.point}
	w.point.resolve[i] = st
	w.breadcrumb[w.depth]++
	w.depth++
	w.point = st
	w.breadcrumb[w.depth] = 0
}

func (w *walker) calcCurrentLength(length, numOperands int) {
	length += w.point.offset
	for i := 0; i < numOperands; i++ {
		sub := w.point.resolve[i]
		if l := sub.length + sub.offset; l > length {
			length = l
		}
	}
	w.point.length = length - w.point.offset
}

// setOutOfBandState positions w at operand index of the nearest enclosing
// ct in other, so another operand's expression can be evaluated there.
func (w *walker) setOutOfBandState(ct *constructor, index int, temp *constructState, other *walker) bool {
	pt := other.point
	depth := other.depth
	for pt.ct != ct {
		if depth <= 0 {
			return false
		}
		depth--
		pt = pt.parent
	}
	sym := ct.operands[index]
	if sym.offsetBase < 0 {
		temp.offset = pt.offset + sym.relOffset
	} else {
		temp.offset = pt.resolve[index].offset
	}
	temp.ct = ct
	temp.length = pt.length
	w.point, w.depth, w.breadcrumb[0] = temp, 0, 0
	return true
}

func (w *walker) instructionByte(i int) byte {
	off := w.point.offset + i
	if off < 0 || off >= len(w.ctx.buf) {
		badData(w, "instruction uses more than %d bytes", maxInsnLen)
	}
	return w.ctx.buf[off]
}

// instructionWord returns the 4 instruction bytes at byte offset off from
// the current constructor, big-endian, as pattern blocks compare them.
func (w *walker) instructionWord(off int) uint32 {
	return uint32(w.instructionByte(off))<<24 | uint32(w.instructionByte(off+1))<<16 |
		uint32(w.instructionByte(off+2))<<8 | uint32(w.instructionByte(off+3))
}

// instructionBits returns size bits starting at bit startbit (most
// significant bit of the current constructor's first byte is bit 0).
func (w *walker) instructionBits(startbit, size int) uint32 {
	first := startbit / 8
	startbit %= 8
	n := (startbit+size-1)/8 + 1
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(w.instructionByte(first+i))
	}
	v >>= uint(8*n - startbit - size)
	return uint32(v & (1<<uint(size) - 1))
}

// contextBits returns size bits of the context starting at startbit.
func (w *walker) contextBits(startbit, size int) uint32 {
	word := startbit / 32
	v := uint64(w.ctx.contextWord(word))<<32 | uint64(w.ctx.contextWord(word+1))
	v >>= uint(64 - startbit%32 - size)
	return uint32(v & (1<<uint(size) - 1))
}

// badDataError is panicked when the bytes do not decode, and recovered by
// the Decoder.
type badDataError struct{ msg string }

func badData(w *walker, format string, args ...any) {
	panic(badDataError{fmt.Sprintf("%#x: ", w.ctx.addr) + fmt.Sprintf(format, args...)})
}

// resolve matches constructors for the instruction at c.addr, following
// Sleigh::resolve.
func (c *parserContext) resolve() {
	w := &walker{ctx: c}
	c.base = &constructState{}
	w.baseState()
	c.delaySlot = 0
	c.commits = c.commits[:0]
	w.point.offset = 0

	ct := c.spec.root.resolve(w)
	w.point.ct = ct
	ct.applyContext(w)
	for w.point != nil {
		ct = w.point.ct
		oper := w.operand()
		n := len(ct.operands)
		for oper < n {
			sym := ct.operands[oper]
			off := w.offset(sym.offsetBase) + sym.relOffset
			w.allocateOperand(oper)
			w.point.offset = off
			if sym.triple != nil {
				if sub := sym.triple.resolve(w); sub != nil {
					w.point.ct = sub
					sub.applyContext(w)
					break
				}
			}
			w.point.length = sym.minLength
			w.popOperand()
			oper++
		}
		if oper >= n {
			w.calcCurrentLength(ct.minLength, n)
			w.popOperand()
			if ct.templ != nil && ct.templ.delaySlot > 0 {
				c.delaySlot = ct.templ.delaySlot
			}
		}
	}
	c.naddr = c.addr + uint64(c.base.length)
}

// resolveHandles computes every operand's varnode handle, following
// Sleigh::resolveHandles.
func (c *parserContext) resolveHandles() {
	w := &walker{ctx: c}
	w.baseState()
	for w.point != nil {
		ct := w.point.ct
		oper := w.operand()
		n := len(ct.operands)
		for oper < n {
			sym := ct.operands[oper]
			w.pushOperand(oper)
			if sym.triple != nil {
				if _, ok := sym.triple.(*subtableSym); ok {
					break
				}
				sym.triple.fixedHandle(&w.point.hand, w)
			} else {
				v := sym.def.value(w)
				w.point.hand = handle{space: c.spec.constSpace, offsetOffset: uint64(v)}
			}
			w.popOperand()
			oper++
		}
		if oper >= n {
			if ct.templ != nil && ct.templ.result != nil {
				ct.templ.result.fix(&w.point.hand, w)
			}
			w.popOperand()
		}
	}
}
