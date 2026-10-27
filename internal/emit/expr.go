package emit

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/ssa"
)

// C operator precedence, higher binds tighter.
const (
	precComma = iota
	precAssign
	precCond
	precOrOr
	precAndAnd
	precOr
	precXor
	precAnd
	precEq
	precRel
	precShift
	precAdd
	precMul
	precUnary
	precPostfix
	precPrimary
)

// cx is a C expression and the precedence of its outermost operator.
type cx struct {
	s string
	p int
}

func wrap(c cx, p int) string {
	if c.p < p {
		return "(" + c.s + ")"
	}
	return c.s
}

func prim(s string) cx { return cx{s, precPrimary} }

func cast(t string, c cx) cx { return cx{"(" + t + ")" + wrap(c, precUnary), precUnary} }

func bin(a cx, op string, b cx, p int) cx {
	return cx{wrap(a, p) + " " + op + " " + wrap(b, p+1), p}
}

// negate is !c.
func negate(c cx) cx { return cx{"!" + wrap(c, precUnary), precUnary} }

// literal prints an integer constant of size bytes.
func (e *funcEmitter) literal(x uint64, size int) string {
	x &= ir.Mask(size)
	s := strconv.FormatUint(x, 10)
	if x >= 10 {
		s = fmt.Sprintf("%#x", x)
	}
	if x > math.MaxUint32 {
		s += "ULL"
	} else if size == 8 && x > math.MaxInt32 {
		s += "U"
	}
	return s
}

// expr renders a value where it is used.
func (e *funcEmitter) expr(v *ssa.Value) cx {
	if v == nil {
		return prim("0")
	}
	if n, ok := e.override[v]; ok {
		return prim(n)
	}
	if n := e.names[v]; n != "" && !e.inline[v] {
		return prim(n)
	}
	switch v.Op {
	case ssa.OpConst:
		if v.Addr && v.Aux != 0 {
			if s, ok := e.u.addr(v.Aux, v.Size); ok {
				return cx{s, precUnary}
			}
		}
		return prim(e.literal(v.Aux, v.Size))
	case ssa.OpUndef, ssa.OpCallOut:
		return prim("0")
	}
	return e.rhs(v)
}

// operand renders v as an integer, or as a float when float is set,
// reinterpreting the bits when v holds the other kind.
func (e *funcEmitter) operand(v *ssa.Value, float bool) cx {
	if float && v.Size != 4 && v.Size != 8 {
		float = false
	}
	if float == e.float[v] {
		return e.expr(v)
	}
	if float {
		if c, ok := v.IsConst(); ok && !v.Addr {
			if s, ok := floatLiteral(c, v.Size); ok {
				return prim(s)
			}
		}
		return prim(e.bitcast("as_"+floatType(v.Size), floatType(v.Size), intType(v.Size)) + "(" + e.expr(v).s + ")")
	}
	return prim(e.bitcast("bits_"+floatType(v.Size), intType(v.Size), floatType(v.Size)) + "(" + e.expr(v).s + ")")
}

// bitcast declares a helper that reinterprets bits of type from as to.
func (e *funcEmitter) bitcast(name, to, from string) string {
	return e.u.helper(name, fmt.Sprintf("static inline %s %s(%s x) { union { %s a; %s b; } u; u.a = x; return u.b; }", to, name, from, from, to))
}

func floatLiteral(bits uint64, size int) (string, bool) {
	if size == 4 {
		f := math.Float32frombits(uint32(bits))
		if math.IsInf(float64(f), 0) || math.IsNaN(float64(f)) {
			return "", false
		}
		s := strconv.FormatFloat(float64(f), 'g', -1, 32)
		return withPoint(s) + "f", true
	}
	f := math.Float64frombits(bits)
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "", false
	}
	return withPoint(strconv.FormatFloat(f, 'g', -1, 64)), true
}

func withPoint(s string) string {
	for _, c := range s {
		if c == '.' || c == 'e' || c == 'n' || c == 'I' {
			return s
		}
	}
	return s + ".0"
}

func (e *funcEmitter) i(v *ssa.Value) cx { return e.operand(v, false) }
func (e *funcEmitter) fl(v *ssa.Value) cx {
	return e.operand(v, true)
}

func (e *funcEmitter) signed(v *ssa.Value) cx {
	if c, ok := v.IsConst(); ok && !v.Addr {
		if s := ir.SignExtend(c, v.Size); s < 0 && s > -0x10000 {
			return cx{strconv.FormatInt(s, 10), precUnary}
		} else if s >= 0 && s < 0x10000 {
			return prim(e.literal(c, v.Size))
		}
	}
	return cast(sintType(v.Size), e.i(v))
}

// pointer renders a load or store address, keeping a symbol a pointer so
// offsets read as fields of it.
func (e *funcEmitter) pointer(v *ssa.Value) string {
	if c, ok := v.IsConst(); ok && v.Addr && c != 0 {
		if s, ok := e.u.ptr(c); ok {
			return s
		}
	}
	return wrap(e.i(v), precUnary)
}

// narrow casts arithmetic on types narrower than int back to size bytes.
func narrow(c cx, size int) cx {
	if size < 4 {
		return cast(intType(size), c)
	}
	return c
}

// cond renders a branch condition, negated when neg is set, inverting
// comparisons rather than wrapping them in "!".
func (e *funcEmitter) cond(v *ssa.Value, neg bool) cx {
	if !neg {
		return e.expr(v)
	}
	if e.inline[v] {
		a := v.Args
		switch v.Op {
		case ir.OpBoolNegate:
			return e.expr(a[0])
		case ir.OpIntEqual:
			return bin(e.i(a[0]), "!=", e.i(a[1]), precEq)
		case ir.OpIntNotEqual:
			return bin(e.i(a[0]), "==", e.i(a[1]), precEq)
		case ir.OpIntLess:
			return bin(e.i(a[0]), ">=", e.i(a[1]), precRel)
		case ir.OpIntLessEqual:
			return bin(e.i(a[0]), ">", e.i(a[1]), precRel)
		case ir.OpIntSLess:
			return bin(e.signed(a[0]), ">=", e.signed(a[1]), precRel)
		case ir.OpIntSLessEqual:
			return bin(e.signed(a[0]), ">", e.signed(a[1]), precRel)
		}
	}
	return negate(e.expr(v))
}

// shift renders a shift, through a helper when the amount may reach the
// operand's width (C leaves that undefined; P-code gives 0 or the sign).
func (e *funcEmitter) shift(v *ssa.Value) cx {
	a, b := v.Args[0], v.Args[1]
	n := v.Size
	bits := uint64(8 * n)
	if c, ok := b.IsConst(); ok && c < bits {
		k := prim(strconv.FormatUint(c, 10))
		switch v.Op {
		case ir.OpIntLeft:
			return narrow(bin(e.i(a), "<<", k, precShift), n)
		case ir.OpIntRight:
			return bin(e.i(a), ">>", k, precShift)
		default:
			return cast(intType(n), bin(e.signed(a), ">>", k, precShift))
		}
	}
	t := intType(n)
	var name, body string
	switch v.Op {
	case ir.OpIntLeft:
		name = "shl_" + t
		body = fmt.Sprintf("return b >= %d ? 0 : (%s)(a << b);", bits, t)
	case ir.OpIntRight:
		name = "shr_" + t
		body = fmt.Sprintf("return b >= %d ? 0 : a >> b;", bits)
	default:
		name = "sar_" + t
		body = fmt.Sprintf("return (%s)((%s)a >> (b >= %d ? %d : b));", t, sintType(n), bits, bits-1)
	}
	e.u.helper(name, fmt.Sprintf("static inline %s %s(%s a, uint64_t b) { %s }", t, name, t, body))
	return prim(fmt.Sprintf("%s(%s, %s)", name, e.i(a).s, e.i(b).s))
}

// flagHelper renders carry and overflow tests.
func (e *funcEmitter) flagHelper(v *ssa.Value) cx {
	a, b := v.Args[0], v.Args[1]
	t, st := intType(a.Size), sintType(a.Size)
	var name, body string
	switch v.Op {
	case ir.OpIntCarry:
		name = "carry_" + t
		body = fmt.Sprintf("return (%s)(a + b) < a;", t)
	case ir.OpIntSCarry:
		name = "scarry_" + t
		body = fmt.Sprintf("%s r; return __builtin_add_overflow((%s)a, (%s)b, &r);", st, st, st)
	default:
		name = "sborrow_" + t
		body = fmt.Sprintf("%s r; return __builtin_sub_overflow((%s)a, (%s)b, &r);", st, st, st)
	}
	e.u.helper(name, fmt.Sprintf("static inline uint8_t %s(%s a, %s b) { %s }", name, t, t, body))
	return prim(fmt.Sprintf("%s(%s, %s)", name, e.i(a).s, e.i(b).s))
}

// rhs renders the operation computing v.
func (e *funcEmitter) rhs(v *ssa.Value) cx {
	a := v.Args
	n := v.Size
	t := intType(n)
	switch v.Op {
	case ir.OpCopy:
		return e.expr(a[0])
	case ssa.OpConst, ssa.OpUndef, ssa.OpCallOut, ssa.OpInput:
		return e.expr(v)
	case ir.OpLoad:
		return cx{fmt.Sprintf("*(%s *)%s", e.ctype(v), e.pointer(a[0])), precUnary}
	case ir.OpCall, ir.OpCallInd, ir.OpCallOther:
		return prim(e.call(v))
	case ir.OpIntAdd:
		if c, ok := a[1].IsConst(); ok && !a[1].Addr {
			if s := ir.SignExtend(c, a[1].Size); s < 0 && s > -0x10000 {
				return narrow(bin(e.i(a[0]), "-", prim(e.literal(uint64(-s), n)), precAdd), n)
			}
		}
		return narrow(bin(e.i(a[0]), "+", e.i(a[1]), precAdd), n)
	case ir.OpIntSub:
		return narrow(bin(e.i(a[0]), "-", e.i(a[1]), precAdd), n)
	case ir.OpIntMult:
		return narrow(bin(e.i(a[0]), "*", e.i(a[1]), precMul), n)
	case ir.OpIntDiv:
		return bin(e.i(a[0]), "/", e.i(a[1]), precMul)
	case ir.OpIntRem:
		return bin(e.i(a[0]), "%", e.i(a[1]), precMul)
	case ir.OpIntSDiv:
		return cast(t, bin(e.signed(a[0]), "/", e.signed(a[1]), precMul))
	case ir.OpIntSRem:
		return cast(t, bin(e.signed(a[0]), "%", e.signed(a[1]), precMul))
	case ir.OpIntAnd:
		return bin(e.i(a[0]), "&", e.i(a[1]), precAnd)
	case ir.OpIntOr:
		return bin(e.i(a[0]), "|", e.i(a[1]), precOr)
	case ir.OpIntXor:
		return bin(e.i(a[0]), "^", e.i(a[1]), precXor)
	case ir.OpIntLeft, ir.OpIntRight, ir.OpIntSRight:
		return e.shift(v)
	case ir.OpInt2Comp:
		return narrow(cx{"-" + wrap(e.i(a[0]), precUnary), precUnary}, n)
	case ir.OpIntNegate:
		return narrow(cx{"~" + wrap(e.i(a[0]), precUnary), precUnary}, n)
	case ir.OpIntZExt:
		return cast(t, e.i(a[0]))
	case ir.OpIntSExt:
		return cast(t, e.signed(a[0]))
	case ir.OpSubpiece:
		c, _ := a[1].IsConst()
		x := e.i(a[0])
		if c > 0 {
			x = bin(x, ">>", prim(strconv.FormatUint(8*c, 10)), precShift)
		}
		if a[0].Size == n && c == 0 {
			return x
		}
		return cast(t, x)
	case ir.OpPiece:
		hi := bin(cast(t, e.i(a[0])), "<<", prim(strconv.Itoa(8*a[1].Size)), precShift)
		return bin(hi, "|", e.i(a[1]), precOr)
	case ir.OpIntEqual:
		return bin(e.i(a[0]), "==", e.i(a[1]), precEq)
	case ir.OpIntNotEqual:
		return bin(e.i(a[0]), "!=", e.i(a[1]), precEq)
	case ir.OpIntLess:
		return bin(e.i(a[0]), "<", e.i(a[1]), precRel)
	case ir.OpIntLessEqual:
		return bin(e.i(a[0]), "<=", e.i(a[1]), precRel)
	case ir.OpIntSLess:
		return bin(e.signed(a[0]), "<", e.signed(a[1]), precRel)
	case ir.OpIntSLessEqual:
		return bin(e.signed(a[0]), "<=", e.signed(a[1]), precRel)
	case ir.OpIntCarry, ir.OpIntSCarry, ir.OpIntSBorrow:
		return e.flagHelper(v)
	case ir.OpBoolNegate:
		return negate(e.i(a[0]))
	case ir.OpBoolAnd:
		return bin(e.i(a[0]), "&&", e.i(a[1]), precAndAnd)
	case ir.OpBoolOr:
		return bin(e.i(a[0]), "||", e.i(a[1]), precOrOr)
	case ir.OpBoolXor:
		return bin(e.i(a[0]), "!=", e.i(a[1]), precEq)
	case ir.OpPopCount:
		return cast(t, prim(fmt.Sprintf("__builtin_popcountll(%s)", e.i(a[0]).s)))
	case ir.OpLzCount:
		w := 8 * a[0].Size
		name := fmt.Sprintf("clz%d", w)
		e.u.helper(name, fmt.Sprintf("static inline uint32_t %s(uint64_t x) { return x ? (uint32_t)__builtin_clzll(x) - %d : %d; }", name, 64-w, w))
		return cast(t, prim(fmt.Sprintf("%s(%s)", name, e.i(a[0]).s)))
	case ir.OpFloatAdd:
		return bin(e.fl(a[0]), "+", e.fl(a[1]), precAdd)
	case ir.OpFloatSub:
		return bin(e.fl(a[0]), "-", e.fl(a[1]), precAdd)
	case ir.OpFloatMult:
		return bin(e.fl(a[0]), "*", e.fl(a[1]), precMul)
	case ir.OpFloatDiv:
		return bin(e.fl(a[0]), "/", e.fl(a[1]), precMul)
	case ir.OpFloatNeg:
		return cx{"-" + wrap(e.fl(a[0]), precUnary), precUnary}
	case ir.OpFloatAbs, ir.OpFloatSqrt, ir.OpFloatCeil, ir.OpFloatFloor, ir.OpFloatRound:
		name := map[ssa.Op]string{ir.OpFloatAbs: "fabs", ir.OpFloatSqrt: "sqrt", ir.OpFloatCeil: "ceil",
			ir.OpFloatFloor: "floor", ir.OpFloatRound: "round"}[v.Op]
		if n == 4 {
			name += "f"
		}
		return prim(fmt.Sprintf("__builtin_%s(%s)", name, e.fl(a[0]).s))
	case ir.OpFloatEqual:
		return bin(e.fl(a[0]), "==", e.fl(a[1]), precEq)
	case ir.OpFloatNotEqual:
		return bin(e.fl(a[0]), "!=", e.fl(a[1]), precEq)
	case ir.OpFloatLess:
		return bin(e.fl(a[0]), "<", e.fl(a[1]), precRel)
	case ir.OpFloatLessEqual:
		return bin(e.fl(a[0]), "<=", e.fl(a[1]), precRel)
	case ir.OpFloatNaN:
		x := e.fl(a[0])
		return bin(x, "!=", x, precEq)
	case ir.OpFloatInt2Float:
		return cast(floatType(n), e.signed(a[0]))
	case ir.OpFloatFloat2Float:
		return cast(floatType(n), e.fl(a[0]))
	case ir.OpFloatTrunc:
		return cast(t, cast(sintType(n), e.fl(a[0])))
	}
	var args []string
	for _, x := range a {
		args = append(args, e.i(x).s)
	}
	name := "__anydec_" + ident(ssa.OpName(v.Op))
	im := e.u.importUse(name)
	im.callers++
	im.ret = t
	return prim(fmt.Sprintf("%s(%s)", name, strings.Join(args, ", ")))
}
