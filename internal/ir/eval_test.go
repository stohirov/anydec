package ir

import (
	"errors"
	"math"
	"testing"
)

func TestEval(t *testing.T) {
	f32 := func(f float32) uint64 { return uint64(math.Float32bits(f)) }
	f64 := math.Float64bits
	for _, c := range []struct {
		code  Opcode
		out   int
		in    []uint64
		sizes []int
		want  uint64
	}{
		{OpIntAdd, 4, []uint64{0xffffffff, 2}, []int{4, 4}, 1},
		{OpIntSub, 1, []uint64{0, 1}, []int{1, 1}, 0xff},
		{OpIntSExt, 4, []uint64{0x80}, []int{1}, 0xffffff80},
		{OpIntZExt, 4, []uint64{0x180}, []int{1}, 0x80},
		{OpIntCarry, 1, []uint64{0xffffffff, 1}, []int{4, 4}, 1},
		{OpIntCarry, 1, []uint64{0xfffffffe, 1}, []int{4, 4}, 0},
		{OpIntSCarry, 1, []uint64{0x7fffffff, 1}, []int{4, 4}, 1},
		{OpIntSBorrow, 1, []uint64{0x80000000, 1}, []int{4, 4}, 1},
		{OpIntSBorrow, 1, []uint64{5, 1}, []int{4, 4}, 0},
		{OpIntSLess, 1, []uint64{0xffffffff, 0}, []int{4, 4}, 1},
		{OpIntLess, 1, []uint64{0xffffffff, 0}, []int{4, 4}, 0},
		{OpIntLeft, 4, []uint64{1, 32}, []int{4, 4}, 0},
		{OpIntRight, 4, []uint64{0x80000000, 31}, []int{4, 4}, 1},
		{OpIntSRight, 4, []uint64{0x80000000, 40}, []int{4, 4}, 0xffffffff},
		{OpIntSDiv, 4, []uint64{0xfffffff9, 2}, []int{4, 4}, 0xfffffffd},
		{OpIntSRem, 4, []uint64{0xfffffff9, 2}, []int{4, 4}, 0xffffffff},
		{OpIntSDiv, 4, []uint64{0x80000000, 0xffffffff}, []int{4, 4}, 0x80000000},
		{OpPiece, 8, []uint64{0x11223344, 0x55667788}, []int{4, 4}, 0x1122334455667788},
		{OpSubpiece, 2, []uint64{0x1122334455667788, 2}, []int{8, 4}, 0x5566},
		{OpLzCount, 4, []uint64{0x00010000}, []int{4}, 15},
		{OpLzCount, 4, []uint64{0}, []int{4}, 32},
		{OpPopCount, 4, []uint64{0xf0f00001}, []int{4}, 9},
		{OpBoolNegate, 1, []uint64{1}, []int{1}, 0},
		{OpFloatAdd, 4, []uint64{f32(1.5), f32(2.25)}, []int{4, 4}, f32(3.75)},
		{OpFloatMult, 8, []uint64{f64(3), f64(-0.5)}, []int{8, 8}, f64(-1.5)},
		{OpFloatLess, 1, []uint64{f32(1), f32(2)}, []int{4, 4}, 1},
		{OpFloatNaN, 1, []uint64{f64(math.NaN())}, []int{8}, 1},
		{OpFloatInt2Float, 4, []uint64{0xfffffffd}, []int{4}, f32(-3)},
		{OpFloatFloat2Float, 8, []uint64{f32(0.1)}, []int{4}, f64(float64(float32(0.1)))},
		{OpFloatTrunc, 4, []uint64{f32(-7.9)}, []int{4}, 0xfffffff9},
		{OpFloatTrunc, 4, []uint64{f32(1e20)}, []int{4}, 0x7fffffff},
		{OpFloatTrunc, 4, []uint64{f64(math.NaN())}, []int{8}, 0},
	} {
		got, err := Eval(c.code, c.out, append([]uint64(nil), c.in...), c.sizes)
		if err != nil {
			t.Errorf("%s%x: %v", c.code, c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s%x = %#x, want %#x", c.code, c.in, got, c.want)
		}
	}
}

func TestEvalErrors(t *testing.T) {
	if _, err := Eval(OpIntDiv, 4, []uint64{1, 0}, []int{4, 4}); !errors.Is(err, ErrDivideByZero) {
		t.Errorf("division by zero: %v", err)
	}
	if _, err := Eval(OpLoad, 4, []uint64{1, 0}, []int{4, 4}); !errors.Is(err, ErrNoEval) {
		t.Errorf("LOAD: %v", err)
	}
	if _, err := Eval(OpCopy, 16, []uint64{1}, []int{16}); !errors.Is(err, ErrNoEval) {
		t.Errorf("16-byte COPY: %v", err)
	}
}

func TestFormatOp(t *testing.T) {
	a := &Arch{Register: func(off uint64, size uint8) string {
		if off == 0x20 && size == 4 {
			return "r0"
		}
		return ""
	}}
	op := Op{Code: OpLoad, Out: &Varnode{SpaceRegister, 0x20, 4}, In: []Varnode{{SpaceConst, uint64(SpaceRAM), 8}, {SpaceUnique, 0x100, 4}}}
	if got, want := a.FormatOp(op), "r0 = LOAD ram, u100:4"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	op = Op{Code: OpCBranch, In: []Varnode{{SpaceRAM, 0x44, 4}, {SpaceRegister, 0x99, 1}}}
	if got, want := a.FormatOp(op), "CBRANCH 0x44, (register, 0x99, 1)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
