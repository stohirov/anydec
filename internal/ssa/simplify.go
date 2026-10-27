package ssa

import (
	"github.com/stohirov/decompile-anything/internal/ir"
)

// Simplify rewrites values with local rules until none applies: constant
// folding (reading constants from read-only memory), algebraic identities,
// partial-register cleanup, and folding of flag computations into plain
// comparisons. It then forwards copies and removes dead values.
func (f *Func) Simplify(img Image) {
	for range 64 {
		changed := false
		for _, b := range f.Blocks {
			for i := 0; i < len(b.Values); i++ {
				v := b.Values[i]
				if f.rewrite(v, img) {
					changed = true
				}
			}
		}
		if f.forwardCopies() {
			changed = true
		}
		if f.cse() {
			changed = true
		}
		if f.mergeBlocks() {
			changed = true
		}
		if !changed {
			break
		}
	}
	f.DeadCode()
}

// insertBefore adds a new value to v's block just before v.
func (f *Func) insertBefore(v *Value, op Op, size int, args ...*Value) *Value {
	n := f.newValue(op, size, v.Origin, args...)
	b := v.Block
	n.Block = b
	for i, x := range b.Values {
		if x == v {
			b.Values = append(b.Values[:i+1], b.Values[i:]...)
			b.Values[i] = n
			return n
		}
	}
	b.Values = append(b.Values, n)
	return n
}

func isCommutative(op Op) bool {
	switch op {
	case ir.OpIntAdd, ir.OpIntMult, ir.OpIntAnd, ir.OpIntOr, ir.OpIntXor, ir.OpIntEqual, ir.OpIntNotEqual,
		ir.OpBoolAnd, ir.OpBoolOr, ir.OpBoolXor:
		return true
	}
	return false
}

// foldable ops compute their result from their inputs alone.
func foldable(op Op) bool {
	switch op {
	case ir.OpLoad, ir.OpStore, ir.OpBranch, ir.OpCBranch, ir.OpBranchInd, ir.OpCall, ir.OpCallInd,
		ir.OpCallOther, ir.OpReturn, ir.OpPhi, ir.OpIndirect, ir.OpCopy:
		return false
	}
	return op < OpConst
}

// keepsAddr lists ops whose result is still an address when an input is.
func keepsAddr(op Op) bool {
	switch op {
	case ir.OpIntAdd, ir.OpIntSub, ir.OpIntAnd, ir.OpIntOr, ir.OpIntZExt, ir.OpSubpiece, ir.OpIntXor:
		return true
	}
	return false
}

func (f *Func) rewrite(v *Value, img Image) bool {
	if v.Op == ir.OpPhi {
		return f.rewritePhi(v)
	}
	if v.Op == ir.OpLoad {
		if a, ok := v.Args[0].IsConst(); ok && img != nil && ir.SpaceID(v.Aux) == ir.SpaceRAM {
			if x, ok := img.ReadOnly(a, v.Size); ok {
				v.copyOf(f.constant(x, v.Size, img.AddressAt(a, v.Size, x)))
				return true
			}
		}
		return false
	}
	if !foldable(v.Op) || len(v.Args) == 0 {
		return false
	}
	if f.fold(v, img) {
		return true
	}
	if isCommutative(v.Op) && len(v.Args) == 2 && v.Args[0].Op == OpConst && v.Args[1].Op != OpConst {
		v.Args[0], v.Args[1] = v.Args[1], v.Args[0]
		return true
	}
	return f.rules(v)
}

// fold evaluates an op whose inputs are all constants.
//
// The result is an address when an address input survives the op, or when
// it lands next to what a relocation in its instruction refers to (the
// halves of a MOVW/MOVT pair, a PC-relative operand).
func (f *Func) fold(v *Value, img Image) bool {
	in := make([]uint64, len(v.Args))
	sizes := make([]int, len(v.Args))
	addr := false
	for i, a := range v.Args {
		x, ok := a.IsConst()
		if !ok || a.Size > 8 {
			return false
		}
		in[i], sizes[i] = x, a.Size
		addr = addr || a.Addr
	}
	if v.Size > 8 {
		return false
	}
	r, err := ir.Eval(v.Op, v.Size, in, sizes)
	if err != nil {
		// No value semantics, or division by zero: leave it for run time.
		return false
	}
	addr = addr && keepsAddr(v.Op)
	if !addr && img != nil && v.Size >= 4 {
		addr = img.AddressAt(v.Origin, f.insnLen(v.Origin), r)
	}
	v.copyOf(f.constant(r, v.Size, addr))
	return true
}

func (f *Func) rewritePhi(v *Value) bool {
	var same *Value
	for _, a := range v.Args {
		if a == v || a == same {
			continue
		}
		if same != nil {
			return false
		}
		same = a
	}
	if same == nil {
		v.reset(OpUndef)
		return true
	}
	v.copyOf(same)
	return true
}

// diff matches a - b, including a + c as a - (-c).
func (f *Func) diff(d *Value) (a, b *Value, ok bool) {
	switch d.Op {
	case ir.OpIntSub:
		return d.Args[0], d.Args[1], true
	case ir.OpIntAdd:
		if c, isc := d.Args[1].IsConst(); isc {
			return d.Args[0], f.Const(-c, d.Size), true
		}
	}
	return nil, nil, false
}

func sameValue(a, b *Value) bool {
	if a == b {
		return true
	}
	x, ok1 := a.IsConst()
	y, ok2 := b.IsConst()
	return ok1 && ok2 && x == y && a.Size == b.Size
}

// signFlags matches {SLESS(a-b, 0), SBORROW(a, b)} in either order.
func (f *Func) signFlags(p, q *Value) (a, b *Value, ok bool) {
	for range 2 {
		if p.Op == ir.OpIntSLess && q.Op == ir.OpIntSBorrow && isZero(p.Args[1]) {
			if x, y, ok := f.diff(p.Args[0]); ok && sameValue(x, q.Args[0]) && sameValue(y, q.Args[1]) {
				return x, y, true
			}
		}
		p, q = q, p
	}
	return nil, nil, false
}

func isZero(v *Value) bool {
	x, ok := v.IsConst()
	return ok && x == 0
}

func isConst(v *Value, x uint64) bool {
	c, ok := v.IsConst()
	return ok && c == x&ir.Mask(v.Size)
}

// isBool reports whether v only ever holds 0 or 1.
func isBool(v *Value) bool { return nz(v, 0) == 1 }

// inverse maps an equality test to its negation.
var inverse = map[Op]Op{
	ir.OpIntEqual: ir.OpIntNotEqual, ir.OpIntNotEqual: ir.OpIntEqual,
}

// negSwap maps an ordering to the one that, with its operands swapped,
// is its negation: !(a < b) is b <= a.
var negSwap = map[Op]Op{
	ir.OpIntSLess: ir.OpIntSLessEqual, ir.OpIntSLessEqual: ir.OpIntSLess,
	ir.OpIntLess: ir.OpIntLessEqual, ir.OpIntLessEqual: ir.OpIntLess,
}

func (f *Func) rules(v *Value) bool {
	a := v.Args
	var c1 uint64
	var k1 bool
	if len(a) == 2 {
		c1, k1 = a[1].IsConst()
	}
	m := ir.Mask(v.Size)
	switch v.Op {
	case ir.OpIntAdd:
		if k1 && c1 == 0 {
			v.copyOf(a[0])
			return true
		}
		if k1 && a[0].Op == ir.OpIntAdd {
			if c0, ok := a[0].Args[1].IsConst(); ok {
				v.reset(ir.OpIntAdd, a[0].Args[0], f.constant(c0+c1, v.Size, a[1].Addr || a[0].Args[1].Addr))
				return true
			}
		}
	case ir.OpIntSub:
		if isZero(a[0]) {
			v.reset(ir.OpInt2Comp, a[1])
			return true
		}
		if a[0] == a[1] {
			v.copyOf(f.Const(0, v.Size))
			return true
		}
		if k1 {
			v.reset(ir.OpIntAdd, a[0], f.Const(-c1, v.Size))
			return true
		}
	case ir.OpIntAnd:
		switch {
		case k1 && c1 == 0:
			v.copyOf(f.Const(0, v.Size))
			return true
		case a[0] == a[1]:
			v.copyOf(a[0])
			return true
		case k1 && nz(a[0], 0)&^c1 == 0:
			v.copyOf(a[0])
			return true
		case k1 && a[0].Op == ir.OpIntAnd:
			if c0, ok := a[0].Args[1].IsConst(); ok {
				v.reset(ir.OpIntAnd, a[0].Args[0], f.Const(c0&c1, v.Size))
				return true
			}
		}
		if k1 && c1&(c1+1) == 0 {
			if f.bitfield(v, a[0], c1) {
				return true
			}
		}
	case ir.OpIntOr:
		switch {
		case k1 && c1 == 0, a[0] == a[1]:
			v.copyOf(a[0])
			return true
		case k1 && c1 == m:
			v.copyOf(a[1])
			return true
		}
		if x := f.reassembled(v); x != nil {
			v.copyOf(x)
			return true
		}
	case ir.OpIntXor:
		switch {
		case k1 && c1 == 0:
			v.copyOf(a[0])
			return true
		case a[0] == a[1]:
			v.copyOf(f.Const(0, v.Size))
			return true
		}
	case ir.OpIntMult:
		switch {
		case k1 && c1 == 1:
			v.copyOf(a[0])
			return true
		case k1 && c1 == 0:
			v.copyOf(f.Const(0, v.Size))
			return true
		}
	case ir.OpIntLeft, ir.OpIntRight, ir.OpIntSRight:
		if k1 && c1 == 0 {
			v.copyOf(a[0])
			return true
		}
		if v.Op == ir.OpIntRight && k1 && c1 < uint64(8*v.Size) {
			if f.bitfield(v, v, uint64(1)<<(uint64(8*v.Size)-c1)-1) {
				return true
			}
		}
		if k1 && c1 >= uint64(8*v.Size) && v.Op != ir.OpIntSRight {
			v.copyOf(f.Const(0, v.Size))
			return true
		}
	case ir.OpIntNegate, ir.OpInt2Comp, ir.OpBoolNegate:
		if a[0].Op == v.Op {
			v.copyOf(a[0].Args[0])
			return true
		}
		if v.Op == ir.OpBoolNegate {
			x := a[0]
			if op, ok := inverse[x.Op]; ok {
				v.reset(op, x.Args...)
				return true
			}
			if op, ok := negSwap[x.Op]; ok {
				v.reset(op, x.Args[1], x.Args[0])
				return true
			}
		}
	case ir.OpIntZExt, ir.OpIntSExt:
		if a[0].Size == v.Size {
			v.copyOf(a[0])
			return true
		}
		if a[0].Op == v.Op || (v.Op == ir.OpIntSExt && a[0].Op == ir.OpIntZExt) {
			v.reset(a[0].Op, a[0].Args[0])
			return true
		}
		if v.Op == ir.OpIntZExt && a[0].Op == ir.OpSubpiece && isZero(a[0].Args[1]) {
			y := a[0].Args[0]
			if y.Size == v.Size && nz(y, 0)&^ir.Mask(a[0].Size) == 0 {
				v.copyOf(y)
				return true
			}
		}
	case ir.OpSubpiece:
		return f.subpiece(v)
	case ir.OpPiece:
		hi, lo := a[0], a[1]
		if hi.Op == ir.OpSubpiece && lo.Op == ir.OpSubpiece && hi.Args[0] == lo.Args[0] &&
			isZero(lo.Args[1]) && isConst(hi.Args[1], uint64(lo.Size)) && hi.Args[0].Size == v.Size {
			v.copyOf(hi.Args[0])
			return true
		}
		if isZero(hi) {
			v.reset(ir.OpIntZExt, lo)
			return true
		}
	case ir.OpIntEqual, ir.OpIntNotEqual:
		return f.equality(v)
	case ir.OpBoolXor:
		if x, y, ok := f.signFlags(a[0], a[1]); ok {
			v.reset(ir.OpIntSLess, x, y)
			return true
		}
		if isZero(a[1]) {
			v.copyOf(a[0])
			return true
		}
	case ir.OpBoolOr:
		return f.boolOr(v)
	case ir.OpBoolAnd:
		return f.boolAnd(v)
	case ir.OpIntSBorrow, ir.OpIntSCarry, ir.OpIntCarry:
		if k1 && c1 == 0 {
			v.copyOf(f.Const(0, 1))
			return true
		}
	case ir.OpIntSLess, ir.OpIntLess:
		if a[0] == a[1] {
			v.copyOf(f.Const(0, 1))
			return true
		}
		if v.Op == ir.OpIntLess && k1 && c1 == 0 {
			v.copyOf(f.Const(0, 1)) // nothing is below zero unsigned
			return true
		}
	case ir.OpIntSLessEqual, ir.OpIntLessEqual:
		if a[0] == a[1] {
			v.copyOf(f.Const(1, 1))
			return true
		}
	}
	return false
}

func (f *Func) equality(v *Value) bool {
	a := v.Args
	eq := v.Op == ir.OpIntEqual
	if x, y, ok := f.signFlags(a[0], a[1]); ok {
		if eq {
			v.reset(ir.OpIntSLessEqual, y, x) // N == V: a >= b
		} else {
			v.reset(ir.OpIntSLess, x, y) // N != V: a < b
		}
		return true
	}
	if a[0] == a[1] {
		v.copyOf(f.Const(boolConst(eq), 1))
		return true
	}
	c, k := a[1].IsConst()
	if !k {
		return false
	}
	x := a[0]
	switch {
	case c == 0 && (x.Op == ir.OpIntSub || x.Op == ir.OpIntXor):
		v.reset(v.Op, x.Args[0], x.Args[1])
		return true
	case x.Op == ir.OpIntAdd && x.Args[1].Op == OpConst:
		v.reset(v.Op, x.Args[0], f.Const(c-x.Args[1].Aux, x.Size))
		return true
	case isBool(x) && (c == 0 || c == 1):
		// x == 0 is !x; x != 0 and x == 1 are x itself.
		b := x
		if x.Op == ir.OpIntZExt {
			b = x.Args[0]
		}
		if b.Size != 1 {
			return false
		}
		if (c == 0) == eq {
			v.reset(ir.OpBoolNegate, b)
		} else {
			v.copyOf(b)
		}
		return true
	case x.Op == ir.OpIntZExt && c&^ir.Mask(x.Args[0].Size) == 0:
		v.reset(v.Op, x.Args[0], f.Const(c, x.Args[0].Size))
		return true
	case x.Op == ir.OpIntZExt:
		v.copyOf(f.Const(boolConst(!eq), 1)) // the constant is out of range
		return true
	}
	return false
}

func boolConst(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// cmpPair matches p and q as an equality and an ordering of the same two
// operands: (a == b, a < b) in either order, with the ordering's operands
// returned as written.
func cmpPair(p, q *Value, eqOp Op, ords ...Op) (ord Op, x, y *Value, ok bool) {
	for range 2 {
		if p.Op == eqOp {
			for _, o := range ords {
				if q.Op != o {
					continue
				}
				if (sameValue(p.Args[0], q.Args[0]) && sameValue(p.Args[1], q.Args[1])) ||
					(sameValue(p.Args[0], q.Args[1]) && sameValue(p.Args[1], q.Args[0])) {
					return o, q.Args[0], q.Args[1], true
				}
			}
		}
		p, q = q, p
	}
	return 0, nil, nil, false
}

func (f *Func) boolOr(v *Value) bool {
	a := v.Args
	switch {
	case a[0] == a[1], isZero(a[1]):
		v.copyOf(a[0])
		return true
	case isConst(a[1], 1):
		v.copyOf(f.Const(1, 1))
		return true
	}
	// a == b || a < b is a <= b.
	if o, x, y, ok := cmpPair(a[0], a[1], ir.OpIntEqual, ir.OpIntSLess, ir.OpIntLess); ok {
		v.reset(map[Op]Op{ir.OpIntSLess: ir.OpIntSLessEqual, ir.OpIntLess: ir.OpIntLessEqual}[o], x, y)
		return true
	}
	return false
}

func (f *Func) boolAnd(v *Value) bool {
	a := v.Args
	switch {
	case a[0] == a[1], isConst(a[1], 1):
		v.copyOf(a[0])
		return true
	case isZero(a[1]):
		v.copyOf(f.Const(0, 1))
		return true
	}
	// a != b && a <= b is a < b.
	if o, x, y, ok := cmpPair(a[0], a[1], ir.OpIntNotEqual, ir.OpIntSLessEqual, ir.OpIntLessEqual); ok {
		v.reset(map[Op]Op{ir.OpIntSLessEqual: ir.OpIntSLess, ir.OpIntLessEqual: ir.OpIntLess}[o], x, y)
		return true
	}
	return false
}

// bitfield rewrites v = (x >> k) & mask, possibly through a truncation,
// when the bits selected are exactly a value OR-ed into x at bit k: flag
// bits packed into a status register and read back.
func (f *Func) bitfield(v, x *Value, mask uint64) bool {
	k := uint64(0)
	for range 2 {
		switch {
		case x.Op == ir.OpSubpiece && isZero(x.Args[1]):
			x = x.Args[0]
		case x.Op == ir.OpIntRight && x.Args[1].Op == OpConst:
			k += x.Args[1].Aux
			x = x.Args[0]
		}
	}
	w := uint64(0)
	for m := mask; m != 0; m >>= 1 {
		w++
	}
	if k == 0 || k >= uint64(8*x.Size) {
		return false
	}
	w = min(w, uint64(8*x.Size)-k)
	y := extract(x, k, w, 0)
	if y == nil || nz(y, 0)&^mask != 0 {
		return false
	}
	switch {
	case y.Size == v.Size:
		v.copyOf(y)
	case y.Size < v.Size:
		v.reset(ir.OpIntZExt, y)
	default:
		v.reset(ir.OpSubpiece, y, f.Const(0, 4))
	}
	return true
}

// extract finds a value equal to bits [lo, lo+w) of x, shifted down, among
// the pieces x is OR-ed together from.
func extract(x *Value, lo, w uint64, depth int) *Value {
	if depth > 8 {
		return nil
	}
	if lo == 0 && nz(x, 0)>>w == 0 {
		return x
	}
	field := (uint64(1)<<w - 1) << lo
	switch x.Op {
	case ir.OpIntOr, ir.OpIntXor:
		for i := range 2 {
			if nz(x.Args[i], 0)&field == 0 {
				return extract(x.Args[1-i], lo, w, depth+1)
			}
		}
	case ir.OpIntLeft:
		if s, ok := x.Args[1].IsConst(); ok && s <= lo {
			return extract(x.Args[0], lo-s, w, depth+1)
		}
	case ir.OpIntZExt:
		if lo+w <= uint64(8*x.Args[0].Size) {
			return extract(x.Args[0], lo, w, depth+1)
		}
	}
	return nil
}

func (f *Func) subpiece(v *Value) bool {
	x := v.Args[0]
	c, ok := v.Args[1].IsConst()
	if !ok {
		return false
	}
	n := uint64(v.Size)
	if c == 0 && int(n) == x.Size {
		v.copyOf(x)
		return true
	}
	if c+n > uint64(x.Size) && c < uint64(x.Size) {
		return false
	}
	bits := ir.Mask(int(n)) << (8 * c)
	if 8*c >= 64 {
		bits = 0
	}
	switch x.Op {
	case ir.OpIntZExt, ir.OpIntSExt:
		y := x.Args[0]
		if c != 0 {
			if c >= uint64(y.Size) && x.Op == ir.OpIntZExt {
				v.copyOf(f.Const(0, v.Size))
				return true
			}
			return false
		}
		switch {
		case int(n) == y.Size:
			v.copyOf(y)
		case int(n) < y.Size:
			v.reset(ir.OpSubpiece, y, f.Const(0, 4))
		default:
			v.reset(x.Op, y)
		}
		return true
	case ir.OpSubpiece:
		if c2, ok := x.Args[1].IsConst(); ok {
			v.reset(ir.OpSubpiece, x.Args[0], f.Const(c+c2, 4))
			return true
		}
	case ir.OpIntOr, ir.OpIntXor:
		for i := range 2 {
			if nz(x.Args[i], 0)&bits == 0 {
				v.reset(ir.OpSubpiece, x.Args[1-i], v.Args[1])
				return true
			}
		}
	case ir.OpIntAnd:
		if k, ok := x.Args[1].IsConst(); ok && k&bits == bits {
			v.reset(ir.OpSubpiece, x.Args[0], v.Args[1])
			return true
		}
	case ir.OpIntLeft:
		if k, ok := x.Args[1].IsConst(); ok && k%8 == 0 {
			sh := k / 8
			switch {
			case c+n <= sh:
				v.copyOf(f.Const(0, v.Size))
				return true
			case c >= sh:
				v.reset(ir.OpSubpiece, x.Args[0], f.Const(c-sh, 4))
				return true
			}
		}
	case ir.OpIntRight:
		if k, ok := x.Args[1].IsConst(); ok && k%8 == 0 && c+k/8+n <= uint64(x.Args[0].Size) {
			v.reset(ir.OpSubpiece, x.Args[0], f.Const(c+k/8, 4))
			return true
		}
	case ir.OpIntDiv, ir.OpIntRem, ir.OpIntSDiv, ir.OpIntSRem:
		// Division of extended operands, truncated back: x86 divides
		// EDX:EAX by a register this way.
		ext := ir.OpIntZExt
		if x.Op == ir.OpIntSDiv || x.Op == ir.OpIntSRem {
			ext = ir.OpIntSExt
		}
		p, q := x.Args[0], x.Args[1]
		if c == 0 && p.Op == ext && q.Op == ext && p.Args[0].Size == int(n) && q.Args[0].Size == int(n) {
			v.reset(x.Op, p.Args[0], q.Args[0])
			return true
		}
	case ir.OpPiece:
		hi, lo := x.Args[0], x.Args[1]
		switch {
		case c+n <= uint64(lo.Size):
			v.reset(ir.OpSubpiece, lo, v.Args[1])
			return true
		case c >= uint64(lo.Size):
			v.reset(ir.OpSubpiece, hi, f.Const(c-uint64(lo.Size), 4))
			return true
		}
	}
	if nz(x, 0)&bits == 0 {
		v.copyOf(f.Const(0, v.Size))
		return true
	}
	return false
}

// reassembled recognizes an OR that puts a value back together from its
// own pieces, (x & keep) | (zext(subpiece(x, k)) << 8k), as partial
// register writes produce when the written part came from the same
// register, and returns x.
func (f *Func) reassembled(v *Value) *Value {
	var src *Value
	var covered uint64
	var parts []*Value
	var collect func(p *Value) bool
	collect = func(p *Value) bool {
		if p.Op == ir.OpIntOr {
			return collect(p.Args[0]) && collect(p.Args[1])
		}
		parts = append(parts, p)
		return len(parts) <= 8
	}
	if !collect(v) {
		return nil
	}
	// The source is what the shifted pieces come from.
	for _, p := range parts {
		q := p
		if q.Op == ir.OpIntLeft {
			q = q.Args[0]
		}
		if q.Op == ir.OpIntZExt && q.Args[0].Op == ir.OpSubpiece {
			src = q.Args[0].Args[0]
			break
		}
		if q.Op == ir.OpIntAnd {
			src = q.Args[0]
			break
		}
	}
	if src == nil || src.Size != v.Size {
		return nil
	}
	for _, p := range parts {
		var bits uint64
		switch {
		case p.Op == ir.OpIntAnd && p.Args[1].Op == OpConst && p.Args[0] == src:
			bits = p.Args[1].Aux
		case p.Op == ir.OpIntZExt && (src.Op == ir.OpIntSExt || src.Op == ir.OpIntZExt) && p.Args[0] == src.Args[0]:
			// The low part of an extension is its operand.
			bits = ir.Mask(p.Args[0].Size)
		default:
			sh := uint64(0)
			q := p
			if q.Op == ir.OpIntLeft && q.Args[1].Op == OpConst {
				sh = q.Args[1].Aux
				q = q.Args[0]
			}
			if q.Op != ir.OpIntZExt {
				return nil
			}
			s := q.Args[0]
			if s.Op != ir.OpSubpiece || s.Args[0] != src || s.Args[1].Op != OpConst || s.Args[1].Aux*8 != sh {
				return nil
			}
			bits = ir.Mask(s.Size) << sh
		}
		covered |= bits
	}
	if src == nil || covered&ir.Mask(v.Size) != ir.Mask(v.Size) {
		return nil
	}
	return src
}

// nz returns a mask of the bits of v that may be nonzero.
func nz(v *Value, depth int) uint64 {
	m := ir.Mask(v.Size)
	if depth > 6 {
		return m
	}
	a := v.Args
	switch v.Op {
	case OpConst:
		return v.Aux
	case ir.OpIntZExt:
		return nz(a[0], depth+1) & ir.Mask(a[0].Size)
	case ir.OpIntAnd:
		return nz(a[0], depth+1) & nz(a[1], depth+1)
	case ir.OpIntOr, ir.OpIntXor:
		return (nz(a[0], depth+1) | nz(a[1], depth+1)) & m
	case ir.OpIntLeft:
		if k, ok := a[1].IsConst(); ok {
			if k >= 64 {
				return 0
			}
			return nz(a[0], depth+1) << k & m
		}
	case ir.OpIntRight:
		if k, ok := a[1].IsConst(); ok {
			if k >= 64 {
				return 0
			}
			return nz(a[0], depth+1) >> k
		}
	case ir.OpSubpiece:
		if k, ok := a[1].IsConst(); ok && k < 8 {
			return nz(a[0], depth+1) >> (8 * k) & m
		}
	case ir.OpIntEqual, ir.OpIntNotEqual, ir.OpIntLess, ir.OpIntLessEqual, ir.OpIntSLess, ir.OpIntSLessEqual,
		ir.OpIntCarry, ir.OpIntSCarry, ir.OpIntSBorrow, ir.OpBoolNegate, ir.OpBoolAnd, ir.OpBoolOr, ir.OpBoolXor,
		ir.OpFloatEqual, ir.OpFloatNotEqual, ir.OpFloatLess, ir.OpFloatLessEqual, ir.OpFloatNaN:
		return 1 & m
	case ir.OpPhi:
		var r uint64
		for _, x := range a {
			if x != v {
				r |= nz(x, depth+1)
			}
		}
		return r & m
	}
	return m
}

// forwardCopies makes every use of a COPY use its source instead.
func (f *Func) forwardCopies() bool {
	changed := false
	fwd := func(x *Value) *Value {
		for x.Op == ir.OpCopy && x.Args[0].Size == x.Size {
			x = x.Args[0]
			changed = true
		}
		return x
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for i, a := range v.Args {
				v.Args[i] = fwd(a)
			}
		}
		if b.Control != nil {
			b.Control = fwd(b.Control)
		}
		for i, r := range b.Results {
			b.Results[i] = fwd(r)
		}
	}
	return changed
}

// DeadCode removes values nothing with an effect depends on.
func (f *Func) DeadCode() {
	live := map[*Value]bool{}
	var work []*Value
	mark := func(v *Value) {
		if v != nil && !live[v] {
			live[v] = true
			work = append(work, v)
		}
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.HasEffect() {
				mark(v)
			}
		}
		mark(b.Control)
		for _, r := range b.Results {
			mark(r)
		}
	}
	for len(work) > 0 {
		v := work[len(work)-1]
		work = work[:len(work)-1]
		for _, a := range v.Args {
			mark(a)
		}
	}
	for _, b := range f.Blocks {
		b.removeValues(func(v *Value) bool { return !live[v] })
	}
}

// cse merges pure values that compute the same thing, keeping the one that
// dominates the other.
func (f *Func) cse() bool {
	type key struct {
		op         Op
		size       int
		aux        uint64
		n          int
		a0, a1, a2 *Value
	}
	keyOf := func(v *Value) (key, bool) {
		if !foldable(v.Op) || len(v.Args) > 3 {
			return key{}, false
		}
		k := key{op: v.Op, size: v.Size, aux: v.Aux, n: len(v.Args)}
		for i, a := range v.Args {
			switch i {
			case 0:
				k.a0 = a
			case 1:
				k.a1 = a
			case 2:
				k.a2 = a
			}
		}
		return k, true
	}
	t := f.Dominators()
	table := map[key]*Value{}
	repl := map[*Value]*Value{}
	var walk func(b *Block)
	walk = func(b *Block) {
		var added []key
		for _, v := range b.Values {
			for i, a := range v.Args {
				v.Args[i] = resolve(repl, a)
			}
			k, ok := keyOf(v)
			if !ok {
				continue
			}
			if w := table[k]; w != nil {
				repl[v] = w
				continue
			}
			table[k] = v
			added = append(added, k)
		}
		for _, c := range t.Children[b] {
			walk(c)
		}
		for _, k := range added {
			delete(table, k)
		}
	}
	walk(f.Blocks[0])
	f.replaceAll(repl)
	return len(repl) > 0
}

// mergeBlocks joins each block that only falls into a successor nothing
// else reaches with that successor.
func (f *Func) mergeBlocks() bool {
	changed := false
	for again := true; again; {
		again = false
		for _, b := range f.Blocks {
			if b.Kind != BlockPlain || len(b.Succs) != 1 {
				continue
			}
			s := b.Succs[0]
			if s == b || s == f.Blocks[0] || len(s.Preds) != 1 {
				continue
			}
			for _, v := range s.Values {
				if v.Op == ir.OpPhi {
					v.copyOf(v.Args[0])
				}
				v.Block = b
			}
			b.Values = append(b.Values, s.Values...)
			b.Kind, b.Control, b.Cases, b.Results, b.End = s.Kind, s.Control, s.Cases, s.Results, s.End
			b.Succs = s.Succs
			for _, x := range s.Succs {
				for i, p := range x.Preds {
					if p == s {
						x.Preds[i] = b
					}
				}
			}
			out := f.Blocks[:0]
			for _, x := range f.Blocks {
				if x != s {
					out = append(out, x)
				}
			}
			f.Blocks = out
			changed, again = true, true
			break
		}
	}
	return changed
}
