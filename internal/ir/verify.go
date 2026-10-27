package ir

import (
	"fmt"
	"sort"
)

// Verify checks the structural invariants every pass may rely on: blocks
// are non-empty, only their last op transfers control, successor counts
// fit that op, predecessor and successor lists mirror each other, every
// block is reachable from the entry, and every op comes from one of the
// function's instructions. A block may lack its fall-through successor
// only in a function with warnings, where flow reached bad bytes.
func (fn *Function) Verify() error {
	if len(fn.Blocks) == 0 {
		return fmt.Errorf("%s: no blocks", fn.Name)
	}
	insns := map[uint64]bool{}
	for _, in := range fn.Insns {
		insns[in.Addr] = true
	}
	in := map[*Block]bool{}
	for _, b := range fn.Blocks {
		in[b] = true
	}
	edges := map[[2]*Block]int{}
	for _, b := range fn.Blocks {
		if len(b.Ops) == 0 {
			return fmt.Errorf("%s: empty block at %#x", fn.Name, b.Start)
		}
		for i, op := range b.Ops {
			if !insns[op.Origin] {
				return fmt.Errorf("%s: op at %#x is from no instruction of the function", fn.Name, op.Origin)
			}
			if i < len(b.Ops)-1 && endsBlock(op.Code) {
				return fmt.Errorf("%s: %s inside the block at %#x", fn.Name, op.Code, b.Start)
			}
		}
		last := b.Ops[len(b.Ops)-1].Code
		n := len(b.Succ)
		// Flow that runs into undecodable bytes stops; the function then
		// carries a warning.
		stops := n == 0 && len(fn.Warnings) > 0
		switch {
		case last == OpCBranch && n != 2,
			last == OpBranch && n > 1,
			last == OpReturn && n != 0,
			!endsBlock(last) && n != 1 && !stops:
			return fmt.Errorf("%s: block at %#x ends in %s with %d successors", fn.Name, b.Start, last, n)
		}
		for _, s := range b.Succ {
			if !in[s] {
				return fmt.Errorf("%s: block at %#x has a successor outside the function", fn.Name, b.Start)
			}
			edges[[2]*Block{b, s}]++
		}
	}
	for _, b := range fn.Blocks {
		for _, p := range b.Pred {
			edges[[2]*Block{p, b}]--
		}
	}
	for e, n := range edges {
		if n != 0 {
			return fmt.Errorf("%s: edge %#x -> %#x is not mirrored in Pred", fn.Name, e[0].Start, e[1].Start)
		}
	}
	seen := map[*Block]bool{fn.Blocks[0]: true}
	work := []*Block{fn.Blocks[0]}
	for len(work) > 0 {
		b := work[len(work)-1]
		work = work[:len(work)-1]
		for _, s := range b.Succ {
			if !seen[s] {
				seen[s] = true
				work = append(work, s)
			}
		}
	}
	if len(seen) != len(fn.Blocks) {
		var lost []uint64
		for _, b := range fn.Blocks {
			if !seen[b] {
				lost = append(lost, b.Start)
			}
		}
		sort.Slice(lost, func(i, j int) bool { return lost[i] < lost[j] })
		return fmt.Errorf("%s: blocks unreachable from the entry: %#x", fn.Name, lost)
	}
	return nil
}

func endsBlock(c Opcode) bool {
	switch c {
	case OpBranch, OpCBranch, OpBranchInd, OpReturn:
		return true
	}
	return false
}
