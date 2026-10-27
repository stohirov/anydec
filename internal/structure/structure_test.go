package structure

import (
	"testing"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/ssa"
)

// graph builds a function whose blocks have the given successors: two
// make a conditional, none a return.
func graph(succ [][]int) *ssa.Func {
	f := &ssa.Func{Name: "g"}
	for i := range succ {
		b := f.NewBlock(ssa.BlockPlain)
		b.Start = uint64(0x100 * (i + 1))
	}
	for i, ss := range succ {
		b := f.Blocks[i]
		switch len(ss) {
		case 0:
			b.Kind = ssa.BlockReturn
		case 2:
			b.Kind = ssa.BlockIf
			b.Control = f.NewValue(b, ir.OpIntEqual, 1, b.Start, f.Const(0, 4), f.Const(1, 4))
		}
		for _, s := range ss {
			b.Succs = append(b.Succs, f.Blocks[s])
			f.Blocks[s].Preds = append(f.Blocks[s].Preds, b)
		}
	}
	return f
}

// placed counts how often each block appears in the structured body.
func placed(s Seq, n map[*ssa.Block]int) {
	for _, x := range s {
		switch x := x.(type) {
		case Seq:
			placed(x, n)
		case Block:
			n[x.B]++
		case If:
			placed(x.Then, n)
			placed(x.Else, n)
		case Loop:
			placed(x.Body, n)
		case Switch:
			for _, c := range x.Cases {
				placed(c.Body, n)
			}
		}
	}
}

func count(s Seq, match func(Node) bool) int {
	n := 0
	for _, x := range s {
		if match(x) {
			n++
		}
		switch x := x.(type) {
		case Seq:
			n += count(x, match)
		case If:
			n += count(x.Then, match) + count(x.Else, match)
		case Loop:
			n += count(x.Body, match)
		}
	}
	return n
}

func checkPlacedOnce(t *testing.T, f *ssa.Func, r *Result) {
	t.Helper()
	n := map[*ssa.Block]int{}
	placed(r.Body, n)
	for _, b := range f.Blocks {
		if n[b] != 1 {
			t.Errorf("block %d placed %d times", b.ID, n[b])
		}
	}
}

func isGoto(n Node) bool { _, ok := n.(Goto); return ok }

func TestDiamond(t *testing.T) {
	// 0 -> 1 | 2 -> 3
	f := graph([][]int{{1, 2}, {3}, {3}, nil})
	r := Structure(f)
	checkPlacedOnce(t, f, r)
	if len(r.Body) != 4 {
		t.Fatalf("body %#v", r.Body)
	}
	iff, ok := r.Body[1].(If)
	if !ok || len(iff.Then) != 1 || len(iff.Else) != 1 {
		t.Errorf("want if/else, got %#v", r.Body[1])
	}
	if count(r.Body, isGoto) != 0 {
		t.Error("goto in a diamond")
	}
}

func TestWhileLoop(t *testing.T) {
	// 0 -> 1; 1 -> 2 | 3; 2 -> 1; 3 returns
	f := graph([][]int{{1}, {2, 3}, {1}, nil})
	r := Structure(f)
	checkPlacedOnce(t, f, r)
	if count(r.Body, func(n Node) bool { _, ok := n.(Loop); return ok }) != 1 {
		t.Errorf("no loop: %#v", r.Body)
	}
	if count(r.Body, func(n Node) bool { _, ok := n.(Break); return ok }) != 1 {
		t.Errorf("loop exit is not a break: %#v", r.Body)
	}
	if count(r.Body, isGoto) != 0 {
		t.Error("goto in a while loop")
	}
}

func TestIrreducibleUsesGoto(t *testing.T) {
	// 0 -> 1 | 2; 1 -> 2 | 3; 2 -> 1; 3 returns: the 1-2 cycle has two
	// entries.
	f := graph([][]int{{1, 2}, {2, 3}, {1}, nil})
	r := Structure(f)
	checkPlacedOnce(t, f, r)
	if count(r.Body, isGoto) == 0 || len(r.Labels) == 0 {
		t.Errorf("irreducible flow without goto: %#v", r.Body)
	}
}
