package ir

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"
)

// ErrNoEval reports an op Eval cannot compute: memory and control flow,
// values wider than 8 bytes, and float formats other than IEEE binary32
// and binary64.
var ErrNoEval = errors.New("op has no value semantics for Eval")

// ErrDivideByZero reports integer division or remainder by zero.
var ErrDivideByZero = errors.New("integer division by zero")

// Mask returns the bits of a size-byte value.
func Mask(size int) uint64 {
	if size >= 8 {
		return ^uint64(0)
	}
	return 1<<(8*size) - 1
}

// SignExtend sign-extends the low size bytes of v.
func SignExtend(v uint64, size int) int64 {
	if size >= 8 {
		return int64(v)
	}
	sh := 64 - 8*size
	return int64(v<<sh) >> sh
}

// Eval computes the output of a value op from its inputs, following P-code
// semantics. in holds each input's value and sizes each input's size in
// bytes; inputs are masked to their sizes and the result to outSize.
func Eval(code Opcode, outSize int, in []uint64, sizes []int) (uint64, error) {
	if outSize > 8 {
		return 0, fmt.Errorf("%s with %d-byte output: %w", code, outSize, ErrNoEval)
	}
	for i := range in {
		if sizes[i] > 8 {
			return 0, fmt.Errorf("%s with %d-byte input: %w", code, sizes[i], ErrNoEval)
		}
		in[i] &= Mask(sizes[i])
	}
	arg := func(i int) uint64 { return in[i] }
	sarg := func(i int) int64 { return SignExtend(in[i], sizes[i]) }
	size := 0
	if len(sizes) > 0 {
		size = sizes[0]
	}
	var out uint64
	switch code {
	case OpCopy, OpCast, OpIntZExt:
		out = arg(0)
	case OpIntSExt:
		out = uint64(sarg(0))
	case OpIntEqual:
		out = b2u(arg(0) == arg(1))
	case OpIntNotEqual:
		out = b2u(arg(0) != arg(1))
	case OpIntSLess:
		out = b2u(sarg(0) < sarg(1))
	case OpIntSLessEqual:
		out = b2u(sarg(0) <= sarg(1))
	case OpIntLess:
		out = b2u(arg(0) < arg(1))
	case OpIntLessEqual:
		out = b2u(arg(0) <= arg(1))
	case OpIntAdd:
		out = arg(0) + arg(1)
	case OpIntSub:
		out = arg(0) - arg(1)
	case OpIntCarry:
		out = b2u((arg(0)+arg(1))&Mask(size) < arg(0))
	case OpIntSCarry:
		a, b := sarg(0), sarg(1)
		r := SignExtend(uint64(a+b), size)
		out = b2u((a < 0) == (b < 0) && (r < 0) != (a < 0))
	case OpIntSBorrow:
		a, b := sarg(0), sarg(1)
		r := SignExtend(uint64(a-b), size)
		out = b2u((a < 0) != (b < 0) && (r < 0) != (a < 0))
	case OpInt2Comp:
		out = -arg(0)
	case OpIntNegate:
		out = ^arg(0)
	case OpIntXor:
		out = arg(0) ^ arg(1)
	case OpIntAnd:
		out = arg(0) & arg(1)
	case OpIntOr:
		out = arg(0) | arg(1)
	case OpIntLeft:
		if s := arg(1); s < 64 {
			out = arg(0) << s
		}
	case OpIntRight:
		if s := arg(1); s < 64 {
			out = arg(0) >> s
		}
	case OpIntSRight:
		out = uint64(sarg(0) >> min(arg(1), 63))
	case OpIntMult:
		out = arg(0) * arg(1)
	case OpIntDiv, OpIntRem, OpIntSDiv, OpIntSRem:
		if arg(1) == 0 {
			return 0, fmt.Errorf("%s: %w", code, ErrDivideByZero)
		}
		switch code {
		case OpIntDiv:
			out = arg(0) / arg(1)
		case OpIntRem:
			out = arg(0) % arg(1)
		case OpIntSDiv:
			out = uint64(sdiv(sarg(0), sarg(1)))
		default:
			out = uint64(srem(sarg(0), sarg(1)))
		}
	case OpPopCount:
		out = uint64(bits.OnesCount64(arg(0)))
	case OpLzCount:
		out = uint64(bits.LeadingZeros64(arg(0)) - (64 - 8*size))
	case OpBoolNegate:
		out = arg(0) ^ 1
	case OpBoolXor:
		out = arg(0) ^ arg(1)
	case OpBoolAnd:
		out = arg(0) & arg(1)
	case OpBoolOr:
		out = arg(0) | arg(1)
	case OpPiece:
		out = arg(0)<<(8*sizes[1]) | arg(1)
	case OpSubpiece:
		if s := arg(1); s < 8 {
			out = arg(0) >> (8 * s)
		}
	default:
		return evalFloat(code, outSize, in, sizes)
	}
	return out & Mask(outSize), nil
}

// sdiv and srem truncate toward zero like C, and wrap the one overflowing
// case (MinInt / -1) instead of panicking.
func sdiv(a, b int64) int64 {
	if b == -1 {
		return -a
	}
	return a / b
}

func srem(a, b int64) int64 {
	if b == -1 {
		return 0
	}
	return a % b
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func toFloat(v uint64, size int) (float64, bool) {
	switch size {
	case 4:
		return float64(math.Float32frombits(uint32(v))), true
	case 8:
		return math.Float64frombits(v), true
	}
	return 0, false
}

func fromFloat(f float64, size int) (uint64, bool) {
	switch size {
	case 4:
		return uint64(math.Float32bits(float32(f))), true
	case 8:
		return math.Float64bits(f), true
	}
	return 0, false
}

func evalFloat(code Opcode, outSize int, in []uint64, sizes []int) (uint64, error) {
	unsupported := fmt.Errorf("%s: %w", code, ErrNoEval)
	if code == OpFloatInt2Float {
		i := SignExtend(in[0], sizes[0])
		switch outSize {
		case 4:
			return uint64(math.Float32bits(float32(i))), nil
		case 8:
			return math.Float64bits(float64(i)), nil
		}
		return 0, unsupported
	}
	if len(in) == 0 {
		return 0, unsupported
	}
	args := make([]float64, len(in))
	for i := range in {
		f, ok := toFloat(in[i], sizes[i])
		if !ok {
			return 0, unsupported
		}
		args[i] = f
	}
	a := args[0]
	var b float64
	if len(args) > 1 {
		b = args[1]
	}
	var r float64
	switch code {
	case OpFloatEqual:
		return b2u(a == b), nil
	case OpFloatNotEqual:
		return b2u(a != b), nil
	case OpFloatLess:
		return b2u(a < b), nil
	case OpFloatLessEqual:
		return b2u(a <= b), nil
	case OpFloatNaN:
		return b2u(math.IsNaN(a)), nil
	case OpFloatTrunc:
		return truncate(a, outSize), nil
	case OpFloatAdd:
		r = a + b
	case OpFloatSub:
		r = a - b
	case OpFloatMult:
		r = a * b
	case OpFloatDiv:
		r = a / b
	case OpFloatNeg:
		r = -a
	case OpFloatAbs:
		r = math.Abs(a)
	case OpFloatSqrt:
		r = math.Sqrt(a)
	case OpFloatCeil:
		r = math.Ceil(a)
	case OpFloatFloor:
		r = math.Floor(a)
	case OpFloatRound:
		r = math.Round(a)
	case OpFloatFloat2Float:
		r = a
	default:
		return 0, unsupported
	}
	// binary64 has more than twice binary32's precision plus two bits, so
	// computing a binary32 op in float64 and rounding the result to binary32
	// gives the correctly rounded binary32 result.
	out, ok := fromFloat(r, outSize)
	if !ok {
		return 0, unsupported
	}
	return out, nil
}

// truncate converts toward zero to a size-byte signed integer, saturating
// out-of-range values and mapping NaN to 0, as ARM's VCVT and AArch64's
// FCVTZS do.
func truncate(f float64, size int) uint64 {
	lo, hi := -math.Ldexp(1, 8*size-1), math.Ldexp(1, 8*size-1)
	var v int64
	switch {
	case math.IsNaN(f):
		v = 0
	case f <= lo:
		v = int64(lo)
	case f >= hi:
		v = int64(uint64(1)<<(8*size-1) - 1)
	default:
		v = int64(f)
	}
	return uint64(v) & Mask(size)
}

// EvalWide is Eval for integer and boolean ops on values of any size, as
// NEON and SSE registers need. Values are unsigned integers; callers
// convert them from memory byte order.
func EvalWide(code Opcode, outSize int, in []*big.Int, sizes []int) (*big.Int, error) {
	mask := func(size int) *big.Int {
		m := new(big.Int).Lsh(big.NewInt(1), uint(8*size))
		return m.Sub(m, big.NewInt(1))
	}
	signed := func(i int) *big.Int {
		v := new(big.Int).And(in[i], mask(sizes[i]))
		if v.Bit(8*sizes[i]-1) == 1 {
			v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(8*sizes[i])))
		}
		return v
	}
	for i := range in {
		in[i] = new(big.Int).And(in[i], mask(sizes[i]))
	}
	b2 := func(b bool) *big.Int {
		if b {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	}
	out := new(big.Int)
	switch code {
	case OpCopy, OpCast, OpIntZExt:
		out.Set(in[0])
	case OpIntSExt:
		out = signed(0)
	case OpIntAdd:
		out.Add(in[0], in[1])
	case OpIntSub:
		out.Sub(in[0], in[1])
	case OpIntMult:
		out.Mul(in[0], in[1])
	case OpIntAnd:
		out.And(in[0], in[1])
	case OpIntOr:
		out.Or(in[0], in[1])
	case OpIntXor:
		out.Xor(in[0], in[1])
	case OpIntNegate:
		out.Not(in[0])
	case OpInt2Comp:
		out.Neg(in[0])
	case OpIntLeft, OpIntRight, OpIntSRight:
		s := in[1].Uint64()
		if !in[1].IsUint64() || s > uint64(8*sizes[0]) {
			s = uint64(8 * sizes[0])
		}
		switch code {
		case OpIntLeft:
			out.Lsh(in[0], uint(s))
		case OpIntRight:
			out.Rsh(in[0], uint(s))
		default:
			out.Rsh(signed(0), uint(s))
		}
	case OpIntEqual:
		out = b2(in[0].Cmp(in[1]) == 0)
	case OpIntNotEqual:
		out = b2(in[0].Cmp(in[1]) != 0)
	case OpIntLess:
		out = b2(in[0].Cmp(in[1]) < 0)
	case OpIntLessEqual:
		out = b2(in[0].Cmp(in[1]) <= 0)
	case OpIntSLess:
		out = b2(signed(0).Cmp(signed(1)) < 0)
	case OpIntSLessEqual:
		out = b2(signed(0).Cmp(signed(1)) <= 0)
	case OpPiece:
		out.Lsh(in[0], uint(8*sizes[1])).Or(out, in[1])
	case OpSubpiece:
		out.Rsh(in[0], uint(8*in[1].Uint64()))
	default:
		return nil, fmt.Errorf("%s on wide values: %w", code, ErrNoEval)
	}
	return out.And(out, mask(outSize)), nil
}
