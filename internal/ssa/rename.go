package ssa

import "github.com/stohirov/decompile-anything/internal/ir"

// DomTree is the dominator tree of a function's blocks.
type DomTree struct {
	Idom     map[*Block]*Block // the entry maps to nil
	Children map[*Block][]*Block
	// Order is a reverse postorder of the blocks reachable from the entry.
	Order []*Block
	index map[*Block]int
}

// Dominators computes the dominator tree with the iterative algorithm of
// Cooper, Harvey and Kennedy.
func (f *Func) Dominators() *DomTree {
	return dominators(f.Blocks[0], func(b *Block) []*Block { return b.Succs }, func(b *Block) []*Block { return b.Preds })
}

// DominatorsOf computes the dominator tree of any graph of blocks, given
// its edges; post-dominators come from the reversed graph.
func DominatorsOf(entry *Block, succs, preds func(*Block) []*Block) *DomTree {
	return dominators(entry, succs, preds)
}

func dominators(entry *Block, succs, preds func(*Block) []*Block) *DomTree {
	t := &DomTree{Idom: map[*Block]*Block{}, Children: map[*Block][]*Block{}, index: map[*Block]int{}}
	seen := map[*Block]bool{}
	var post []*Block
	var visit func(*Block)
	visit = func(b *Block) {
		seen[b] = true
		for _, s := range succs(b) {
			if !seen[s] {
				visit(s)
			}
		}
		post = append(post, b)
	}
	visit(entry)
	for i := len(post) - 1; i >= 0; i-- {
		t.index[post[i]] = len(t.Order)
		t.Order = append(t.Order, post[i])
	}
	idom := map[*Block]*Block{entry: entry}
	intersect := func(a, b *Block) *Block {
		for a != b {
			for t.index[a] > t.index[b] {
				a = idom[a]
			}
			for t.index[b] > t.index[a] {
				b = idom[b]
			}
		}
		return a
	}
	for changed := true; changed; {
		changed = false
		for _, b := range t.Order[1:] {
			var d *Block
			for _, p := range preds(b) {
				if idom[p] == nil {
					continue
				}
				if d == nil {
					d = p
				} else {
					d = intersect(p, d)
				}
			}
			if d != nil && idom[b] != d {
				idom[b] = d
				changed = true
			}
		}
	}
	for _, b := range t.Order {
		if b == entry {
			t.Idom[b] = nil
			continue
		}
		t.Idom[b] = idom[b]
		t.Children[idom[b]] = append(t.Children[idom[b]], b)
	}
	return t
}

// Dominates reports whether a dominates b.
func (t *DomTree) Dominates(a, b *Block) bool {
	for ; b != nil; b = t.Idom[b] {
		if a == b {
			return true
		}
	}
	return false
}

// frontiers returns each block's dominance frontier.
func (t *DomTree) frontiers() map[*Block][]*Block {
	df := map[*Block][]*Block{}
	for _, b := range t.Order {
		if len(b.Preds) < 2 {
			continue
		}
		for _, p := range b.Preds {
			if _, ok := t.index[p]; !ok {
				continue
			}
			for r := p; r != nil && r != t.Idom[b]; r = t.Idom[r] {
				if l := df[r]; len(l) == 0 || l[len(l)-1] != b {
					df[r] = append(l, b)
				}
			}
		}
	}
	return df
}

// rename removes every OpRead and OpWrite: reads become the value last
// written along the dominator tree, with phis placed at the iterated
// dominance frontiers of the variables live across blocks (semi-pruned
// SSA), and reads before any write become the variable's input.
func (f *Func) rename() {
	t := f.Dominators()
	df := t.frontiers()

	defs := map[*Var][]*Block{}
	global := map[*Var]bool{}
	for _, b := range f.Blocks {
		written := map[*Var]bool{}
		for _, v := range b.Values {
			switch v.Op {
			case OpRead:
				if !written[v.Var] {
					global[v.Var] = true
				}
			case OpWrite:
				if !written[v.Var] {
					written[v.Var] = true
					defs[v.Var] = append(defs[v.Var], b)
				}
			}
		}
	}
	// Results and call arguments read variables too, but only through
	// OpRead values, so global already covers them.
	phis := map[*Block][]*Value{}
	for vr, blocks := range defs {
		if !global[vr] {
			continue
		}
		has := map[*Block]bool{}
		work := append([]*Block{}, blocks...)
		for len(work) > 0 {
			b := work[len(work)-1]
			work = work[:len(work)-1]
			for _, d := range df[b] {
				if has[d] {
					continue
				}
				has[d] = true
				phi := f.newValue(ir.OpPhi, vr.Size, d.Start)
				phi.Var, phi.Block = vr, d
				phi.Args = make([]*Value, len(d.Preds))
				phis[d] = append(phis[d], phi)
				work = append(work, d)
			}
		}
	}
	for b, ps := range phis {
		b.Values = append(ps, b.Values...)
	}

	repl := map[*Value]*Value{}
	stacks := map[*Var][]*Value{}
	top := func(vr *Var) *Value {
		if s := stacks[vr]; len(s) > 0 {
			return s[len(s)-1]
		}
		return f.Input(vr)
	}
	var walk func(b *Block)
	walk = func(b *Block) {
		var pushed []*Var
		for _, v := range b.Values {
			switch {
			case v.Op == ir.OpPhi && v.Var != nil && v.Args != nil && phiOf(phis[b], v):
				stacks[v.Var] = append(stacks[v.Var], v)
				pushed = append(pushed, v.Var)
			case v.Op == OpRead:
				repl[v] = top(v.Var)
			case v.Op == OpWrite:
				stacks[v.Var] = append(stacks[v.Var], resolve(repl, v.Args[0]))
				pushed = append(pushed, v.Var)
			}
		}
		for _, s := range b.Succs {
			i := s.predIndex(b)
			for _, phi := range phis[s] {
				phi.Args[i] = top(phi.Var)
			}
		}
		for _, c := range t.Children[b] {
			walk(c)
		}
		for _, vr := range pushed {
			stacks[vr] = stacks[vr][:len(stacks[vr])-1]
		}
	}
	walk(f.Blocks[0])

	for _, b := range f.Blocks {
		b.removeValues(func(v *Value) bool { return v.Op == OpRead || v.Op == OpWrite })
	}
	f.replaceAll(repl)
}

func phiOf(ps []*Value, v *Value) bool {
	for _, p := range ps {
		if p == v {
			return true
		}
	}
	return false
}

func resolve(repl map[*Value]*Value, v *Value) *Value {
	for {
		r, ok := repl[v]
		if !ok {
			return v
		}
		v = r
	}
}

// replaceAll rewrites every use of a key of repl to its value.
func (f *Func) replaceAll(repl map[*Value]*Value) {
	if len(repl) == 0 {
		return
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for i, a := range v.Args {
				if a != nil {
					v.Args[i] = resolve(repl, a)
				}
			}
		}
		if b.Control != nil {
			b.Control = resolve(repl, b.Control)
		}
		for i, r := range b.Results {
			b.Results[i] = resolve(repl, r)
		}
	}
	for i, p := range f.Params {
		f.Params[i] = resolve(repl, p)
	}
}
