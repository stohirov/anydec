package emit

import (
	"strings"
	"testing"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/loader"
	"github.com/stohirov/decompile-anything/internal/ssa"
)

func regVar(name string, off int64) *ssa.Var {
	return &ssa.Var{Space: ir.SpaceRegister, Offset: off, Size: 4, Name: name}
}

func phi(f *ssa.Func, b *ssa.Block, v *ssa.Var) *ssa.Value {
	p := f.NewValue(b, ir.OpPhi, 4, b.Start)
	p.Var = v
	return p
}

func link(from, to *ssa.Block) {
	from.Succs = append(from.Succs, to)
	to.Preds = append(to.Preds, from)
}

// swapLoop is: a = x; b = y; for (i = 0; i < n; i++) swap a and b;
// return a. Its phis exchange values on the back edge, so the copies need
// a temporary.
func swapLoop() *ssa.Func {
	f := &ssa.Func{Name: "swap", Arch: &ir.Arch{PointerSize: 4}}
	x, y, n := f.Input(regVar("r0", 0)), f.Input(regVar("r1", 4)), f.Input(regVar("r2", 8))
	f.Params = []*ssa.Value{x, y, n}
	r0 := ir.Varnode{Space: ir.SpaceRegister, Offset: 0, Size: 4}
	f.Proto = &ssa.Proto{Known: true, Returns: []ssa.Ret{{Reg: r0, Size: 4}}}
	for i := range 3 {
		f.Proto.Params = append(f.Proto.Params, ssa.Param{Reg: ir.Varnode{Space: ir.SpaceRegister, Offset: uint64(4 * i), Size: 4}, Size: 4})
	}
	entry, head, body, exit := f.NewBlock(ssa.BlockPlain), f.NewBlock(ssa.BlockIf), f.NewBlock(ssa.BlockPlain), f.NewBlock(ssa.BlockReturn)
	for i, b := range f.Blocks {
		b.Start = uint64(0x10 * (i + 1))
	}
	link(entry, head)
	link(head, exit) // false
	link(head, body) // true
	link(body, head)
	a, b, i := phi(f, head, regVar("a", 0x20)), phi(f, head, regVar("b", 0x24)), phi(f, head, regVar("i", 0x28))
	inc := f.NewValue(body, ir.OpIntAdd, 4, body.Start, i, f.Const(1, 4))
	a.Args = []*ssa.Value{x, b}
	b.Args = []*ssa.Value{y, a}
	i.Args = []*ssa.Value{f.Const(0, 4), inc}
	head.Control = f.NewValue(head, ir.OpIntSLess, 1, head.Start, i, n)
	exit.Results = []*ssa.Value{a}
	return f
}

func TestParallelCopiesUseTemporary(t *testing.T) {
	f := swapLoop()
	u := &Unit{Prog: &loader.Program{}, Funcs: []*ssa.Func{f}}
	src := u.Function(f)
	for _, want := range []string{"uint32_t swap(uint32_t a1, uint32_t a2, uint32_t a3)", "a = a1;", "b = a2;", "return a;"} {
		if !strings.Contains(src, want) {
			t.Errorf("missing %q:\n%s", want, src)
		}
	}
	// The back edge must save one of a and b before overwriting it.
	if !strings.Contains(src, "_old = ") {
		t.Errorf("swap without a temporary:\n%s", src)
	}
	lines := strings.Split(src, "\n")
	var order []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "a = b;" || strings.HasPrefix(l, "b = a_") || strings.Contains(l, "_old = ") {
			order = append(order, l)
		}
	}
	if len(order) != 3 || !strings.Contains(order[0], "_old = ") {
		t.Errorf("copy order %q:\n%s", order, src)
	}
}

func TestLiterals(t *testing.T) {
	e := &funcEmitter{}
	for _, tt := range []struct {
		x    uint64
		size int
		want string
	}{{7, 4, "7"}, {0x10, 4, "0x10"}, {0xffffffff, 4, "0xffffffff"}, {0x100000000, 8, "0x100000000ULL"}, {0x80000000, 8, "0x80000000U"}} {
		if got := e.literal(tt.x, tt.size); got != tt.want {
			t.Errorf("literal(%#x, %d) = %s, want %s", tt.x, tt.size, got, tt.want)
		}
	}
	if s, ok := floatLiteral(0x3f800000, 4); !ok || s != "1.0f" {
		t.Errorf("1.0f printed as %q", s)
	}
	if s, ok := floatLiteral(0x3fb999999999999a, 8); !ok || s != "0.1" {
		t.Errorf("0.1 printed as %q", s)
	}
}
