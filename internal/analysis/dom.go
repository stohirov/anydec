package analysis

import "github.com/stohirov/decompile-anything/internal/ir"

// idoms returns each block's immediate dominator (the entry block maps to
// itself), using the iterative algorithm of Cooper, Harvey and Kennedy.
// Blocks unreachable from the entry are absent.
func idoms(fn *ir.Function) map[*ir.Block]*ir.Block {
	if len(fn.Blocks) == 0 {
		return nil
	}
	// Reverse postorder from the entry.
	var order []*ir.Block
	seen := map[*ir.Block]bool{}
	var visit func(*ir.Block)
	visit = func(b *ir.Block) {
		seen[b] = true
		for _, s := range b.Succ {
			if !seen[s] {
				visit(s)
			}
		}
		order = append(order, b)
	}
	entry := fn.Blocks[0]
	visit(entry)
	index := map[*ir.Block]int{}
	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}
	for i, b := range order {
		index[b] = i
	}

	idom := map[*ir.Block]*ir.Block{entry: entry}
	intersect := func(a, b *ir.Block) *ir.Block {
		for a != b {
			for index[a] > index[b] {
				a = idom[a]
			}
			for index[b] > index[a] {
				b = idom[b]
			}
		}
		return a
	}
	for changed := true; changed; {
		changed = false
		for _, b := range order[1:] {
			var d *ir.Block
			for _, p := range b.Pred {
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
	return idom
}
