package sleigh

import (
	"fmt"
	"strings"
)

// Symbols mirror Ghidra's SleighSymbol hierarchy, keeping only what decoding
// needs at run time.

type symBase struct {
	name string
	id   int
}

func (b *symBase) base() *symBase { return b }

type symbol interface {
	base() *symBase
	decode(d *specDecoder, e *element)
}

// tripleSymbol is a symbol usable as a constructor operand: it may select a
// sub-constructor, has a pattern value, resolves to a varnode handle and
// prints itself.
type tripleSymbol interface {
	symbol
	// resolve returns the sub-constructor the operand decodes to, or nil.
	// It panics with badData when the encoding has no valid meaning.
	resolve(w *walker) *constructor
	patternExpr() expr
	fixedHandle(h *handle, w *walker)
	print(b *strings.Builder, w *walker)
}

func printValue(b *strings.Builder, v int64) {
	if v >= 0 {
		fmt.Fprintf(b, "0x%x", v)
	} else {
		fmt.Fprintf(b, "-0x%x", uint64(-v))
	}
}

type userOpSym struct {
	symBase
	index int
}

// epsilonSym is the empty operand: value zero, prints "0".
type epsilonSym struct{ symBase }

func (*epsilonSym) resolve(*walker) *constructor { return nil }
func (*epsilonSym) patternExpr() expr            { return constValue(0) }
func (*epsilonSym) fixedHandle(h *handle, w *walker) {
	*h = handle{space: w.ctx.spec.constSpace}
}
func (*epsilonSym) print(b *strings.Builder, _ *walker) { b.WriteByte('0') }

// valueSym is an instruction field or expression used as a number.
type valueSym struct {
	symBase
	val expr
}

func (*valueSym) resolve(*walker) *constructor { return nil }
func (v *valueSym) patternExpr() expr          { return v.val }
func (v *valueSym) fixedHandle(h *handle, w *walker) {
	*h = handle{space: w.ctx.spec.constSpace, offsetOffset: uint64(v.val.value(w))}
}
func (v *valueSym) print(b *strings.Builder, w *walker) { printValue(b, v.val.value(w)) }

// valueMapSym maps a field to values from a table ("attach values").
type valueMapSym struct {
	valueSym
	table []int64
}

const badBeef = 0xBADBEEF // marks table entries with no value

func (v *valueMapSym) lookup(w *walker) int64 {
	i := v.val.value(w)
	if i < 0 || i >= int64(len(v.table)) || v.table[i] == badBeef {
		badData(w, "no entry in value table %s", v.name)
	}
	return v.table[i]
}

func (v *valueMapSym) resolve(w *walker) *constructor { v.lookup(w); return nil }
func (v *valueMapSym) fixedHandle(h *handle, w *walker) {
	*h = handle{space: w.ctx.spec.constSpace, offsetOffset: uint64(v.lookup(w))}
}
func (v *valueMapSym) print(b *strings.Builder, w *walker) { printValue(b, v.lookup(w)) }

// nameSym maps a field to names ("attach names").
type nameSym struct {
	valueSym
	names []string
}

func (n *nameSym) lookup(w *walker) string {
	i := n.val.value(w)
	if i < 0 || i >= int64(len(n.names)) || n.names[i] == "\t" {
		badData(w, "no entry in name table %s", n.name)
	}
	return n.names[i]
}

func (n *nameSym) resolve(w *walker) *constructor      { n.lookup(w); return nil }
func (n *nameSym) print(b *strings.Builder, w *walker) { b.WriteString(n.lookup(w)) }

// varnodeSym is a fixed varnode, usually a register.
type varnodeSym struct {
	symBase
	space  *Space
	offset uint64
	size   int
}

func (*varnodeSym) resolve(*walker) *constructor { return nil }
func (*varnodeSym) patternExpr() expr            { return constValue(0) }
func (v *varnodeSym) fixedHandle(h *handle, _ *walker) {
	*h = handle{space: v.space, offsetOffset: v.offset, size: v.size}
}
func (v *varnodeSym) print(b *strings.Builder, _ *walker) { b.WriteString(v.name) }

// contextSym is a context variable used as a value.
type contextSym struct {
	valueSym
	vn        *varnodeSym
	low, high int
	flow      bool
}

// varListSym maps a field to registers ("attach variables").
type varListSym struct {
	valueSym
	regs []*varnodeSym
}

func (v *varListSym) lookup(w *walker) *varnodeSym {
	i := v.val.value(w)
	if i < 0 || i >= int64(len(v.regs)) || v.regs[i] == nil {
		badData(w, "no entry in register list %s", v.name)
	}
	return v.regs[i]
}

func (v *varListSym) resolve(w *walker) *constructor { v.lookup(w); return nil }
func (v *varListSym) fixedHandle(h *handle, w *walker) {
	r := v.lookup(w)
	*h = handle{space: r.space, offsetOffset: r.offset, size: r.size}
}
func (v *varListSym) print(b *strings.Builder, w *walker) { b.WriteString(v.lookup(w).name) }

// operandSym is one operand of a constructor.
type operandSym struct {
	symBase
	hand       int // index of this operand in its constructor
	relOffset  int
	offsetBase int // operand the offset is relative to; -1 for the constructor start
	minLength  int
	codeAddr   bool
	local      expr         // the operand's own value expression
	triple     tripleSymbol // defining symbol, or
	def        expr         // defining expression
}

func (*operandSym) resolve(*walker) *constructor { return nil }
func (o *operandSym) patternExpr() expr          { return o.local }
func (o *operandSym) fixedHandle(h *handle, w *walker) {
	*h = w.point.resolve[o.hand].hand
}

func (o *operandSym) print(b *strings.Builder, w *walker) {
	w.pushOperand(o.hand)
	switch t := o.triple.(type) {
	case nil:
		printValue(b, o.def.value(w))
	case *subtableSym:
		w.point.ct.printAll(b, w)
	default:
		t.print(b, w)
	}
	w.popOperand()
}

// startSym is inst_start, endSym inst_next, next2Sym inst_next2.
type startSym struct{ symBase }
type endSym struct{ symBase }
type next2Sym struct{ symBase }

func (*startSym) resolve(*walker) *constructor { return nil }
func (*startSym) patternExpr() expr            { return startValue{} }
func (*startSym) fixedHandle(h *handle, w *walker) {
	sp := w.ctx.spec.DefaultSpace
	*h = handle{space: sp, offsetOffset: w.ctx.addr, size: sp.Size}
}
func (*startSym) print(b *strings.Builder, w *walker) { fmt.Fprintf(b, "0x%x", w.ctx.addr) }

func (*endSym) resolve(*walker) *constructor { return nil }
func (*endSym) patternExpr() expr            { return endValue{} }
func (*endSym) fixedHandle(h *handle, w *walker) {
	sp := w.ctx.spec.DefaultSpace
	*h = handle{space: sp, offsetOffset: w.naddr(), size: sp.Size}
}
func (*endSym) print(b *strings.Builder, w *walker) { fmt.Fprintf(b, "0x%x", w.naddr()) }

func (*next2Sym) resolve(*walker) *constructor { return nil }
func (*next2Sym) patternExpr() expr            { return next2Value{} }
func (*next2Sym) fixedHandle(h *handle, w *walker) {
	sp := w.ctx.spec.DefaultSpace
	*h = handle{space: sp, offsetOffset: w.n2addr(), size: sp.Size}
}
func (*next2Sym) print(b *strings.Builder, w *walker) { fmt.Fprintf(b, "0x%x", w.n2addr()) }

// subtableSym is a table of constructors chosen by a decision tree.
type subtableSym struct {
	symBase
	cts  []*constructor
	tree *decisionNode
}

func (t *subtableSym) resolve(w *walker) *constructor { return t.tree.resolve(w) }
func (t *subtableSym) patternExpr() expr {
	panic(fmt.Sprintf("sleigh: subtable %s used in an expression", t.name))
}
func (t *subtableSym) fixedHandle(*handle, *walker) {
	panic(fmt.Sprintf("sleigh: subtable %s used as a value", t.name))
}
func (t *subtableSym) print(*strings.Builder, *walker) {
	panic(fmt.Sprintf("sleigh: subtable %s printed directly", t.name))
}

// constructor is one line of a SLEIGH table: a pattern, operands, display
// syntax, context changes and p-code templates.
type constructor struct {
	parent          *subtableSym
	id              int
	line            int
	minLength       int
	operands        []*operandSym
	print           []printPiece
	firstWhitespace int // index of the piece separating mnemonic and body; -1 if none
	flowThru        int // operand printed alone, or -1
	context         []contextChange
	templ           *constructTpl
	named           []*constructTpl
}

type printPiece struct {
	text    string
	operand int // >= 0 when the piece prints an operand
}

func (ct *constructor) printPieces(b *strings.Builder, w *walker, pieces []printPiece) {
	for _, p := range pieces {
		if p.operand >= 0 {
			ct.operands[p.operand].print(b, w)
		} else {
			b.WriteString(p.text)
		}
	}
}

func (ct *constructor) printAll(b *strings.Builder, w *walker) {
	ct.printPieces(b, w, ct.print)
}

// flowsThru reports whether the constructor only prints a subtable operand,
// whose mnemonic and body then stand in for its own.
func (ct *constructor) flowsThru() bool {
	if ct.flowThru < 0 {
		return false
	}
	_, ok := ct.operands[ct.flowThru].triple.(*subtableSym)
	return ok
}

func (ct *constructor) printMnemonic(b *strings.Builder, w *walker) {
	if ct.flowsThru() {
		w.pushOperand(ct.flowThru)
		w.point.ct.printMnemonic(b, w)
		w.popOperand()
		return
	}
	end := len(ct.print)
	if ct.firstWhitespace >= 0 {
		end = min(ct.firstWhitespace, end)
	}
	ct.printPieces(b, w, ct.print[:end])
}

func (ct *constructor) printBody(b *strings.Builder, w *walker) {
	if ct.flowsThru() {
		w.pushOperand(ct.flowThru)
		w.point.ct.printBody(b, w)
		w.popOperand()
		return
	}
	if ct.firstWhitespace < 0 || ct.firstWhitespace+1 >= len(ct.print) {
		return
	}
	ct.printPieces(b, w, ct.print[ct.firstWhitespace+1:])
}

func (ct *constructor) applyContext(w *walker) {
	for _, c := range ct.context {
		c.apply(w)
	}
}

// contextChange is a context operation run when a constructor matches.
type contextChange interface{ apply(w *walker) }

// contextOp sets bits of the local context from an expression.
type contextOp struct {
	val   expr
	num   int
	shift int
	mask  uint32
}

func (c *contextOp) apply(w *walker) {
	v := uint32(c.val.value(w)) << c.shift
	w.ctx.setContextWord(c.num, v, c.mask)
}

// contextCommit (globalset) carries the current context bits to the address
// a symbol names, such as the next instruction.
type contextCommit struct {
	sym  tripleSymbol
	num  int
	mask uint32
	flow bool
}

func (c *contextCommit) apply(w *walker) {
	w.ctx.commits = append(w.ctx.commits, contextSet{
		sym:   c.sym,
		point: w.point,
		num:   c.num,
		mask:  c.mask,
		value: w.ctx.context[c.num] & c.mask,
		flow:  c.flow,
	})
}

// decisionNode picks a constructor by testing instruction or context bits.
type decisionNode struct {
	context  bool
	startBit int
	size     int // 0 for a leaf, which tests its pairs in order
	pairs    []decisionPair
	kids     []*decisionNode
}

type decisionPair struct {
	pat disjointPattern
	ct  *constructor
}

func (n *decisionNode) resolve(w *walker) *constructor {
	for n.size > 0 {
		var v uint32
		if n.context {
			v = w.contextBits(n.startBit, n.size)
		} else {
			v = w.instructionBits(n.startBit, n.size)
		}
		n = n.kids[v]
	}
	for _, p := range n.pairs {
		if p.pat.match(w) {
			return p.ct
		}
	}
	badData(w, "unable to resolve constructor")
	return nil
}
