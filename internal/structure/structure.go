// Package structure turns a CFG back into if, while, switch, break and
// continue, and falls back to a labelled goto only where no structured form
// fits.
//
// Every block is placed exactly once, in a walk that follows control flow:
// a conditional's two arms run until they meet at the block's immediate
// post-dominator, which follows the if; a loop's body runs until it
// returns to the header (continue) or leaves for the loop's follow block
// (break). An edge to a block already placed elsewhere becomes a goto, so
// the result is correct for any CFG, irreducible ones included; for the
// reducible graphs compilers emit, gotos are rare.
package structure

import (
	"github.com/stohirov/decompile-anything/internal/ssa"
)

// Node is an element of a structured function body.
type Node interface{ node() }

// Seq is a sequence of nodes run in order.
type Seq []Node

// Block runs a basic block's statements (not its terminator).
type Block struct{ B *ssa.Block }

// If runs Then when B's control is true, Else otherwise.
type If struct {
	B          *ssa.Block
	Then, Else Seq
}

// Loop repeats Body forever; Break and Return leave it.
type Loop struct{ Body Seq }

// Switch dispatches on B's control. Each case lists the targets' blocks
// whose jump-table entries select it.
type Switch struct {
	B     *ssa.Block
	Cases []Case
}

// Case is one switch arm.
type Case struct {
	Target *ssa.Block
	Body   Seq
}

// Break leaves the innermost loop or switch; Continue restarts the
// innermost loop.
type (
	Break    struct{}
	Continue struct{}
)

// Goto jumps to the labelled block.
type Goto struct{ Target *ssa.Block }

// Return ends B, a return block.
type Return struct{ B *ssa.Block }

// Stop marks flow that cannot continue (undecodable code).
type Stop struct{ B *ssa.Block }

func (Seq) node()      {}
func (Block) node()    {}
func (If) node()       {}
func (Loop) node()     {}
func (Switch) node()   {}
func (Break) node()    {}
func (Continue) node() {}
func (Goto) node()     {}
func (Return) node()   {}
func (Stop) node()     {}

// Result is a structured function: its body and the blocks gotos target.
type Result struct {
	Body   Seq
	Labels map[*ssa.Block]bool
}

type loop struct {
	header *ssa.Block
	body   map[*ssa.Block]bool
	follow *ssa.Block
}

type ctx struct {
	follow *ssa.Block // where the enclosing construct continues
	loop   *loop
	// inSwitch is set inside a switch nested in loop, where C's break
	// would leave the switch rather than the loop.
	inSwitch bool
}

type structurer struct {
	f       *ssa.Func
	dom     *ssa.DomTree
	ipdom   map[*ssa.Block]*ssa.Block
	loops   map[*ssa.Block]*loop
	placed  map[*ssa.Block]bool
	labels  map[*ssa.Block]bool
	entered map[*ssa.Block]bool
}

// Structure computes the structured form of f.
func Structure(f *ssa.Func) *Result {
	s := &structurer{
		f: f, dom: f.Dominators(), placed: map[*ssa.Block]bool{}, labels: map[*ssa.Block]bool{},
		entered: map[*ssa.Block]bool{},
	}
	s.ipdom = postDominators(f)
	s.findLoops()
	body := s.seq(f.Blocks[0], ctx{})
	return &Result{Body: body, Labels: s.labels}
}

// postDominators returns each block's immediate post-dominator, nil when
// it is the virtual exit or the block cannot reach an exit.
func postDominators(f *ssa.Func) map[*ssa.Block]*ssa.Block {
	exit := &ssa.Block{ID: -1}
	for _, b := range f.Blocks {
		if len(b.Succs) == 0 {
			exit.Preds = append(exit.Preds, b)
		}
	}
	succ := func(b *ssa.Block) []*ssa.Block {
		if b == exit {
			return exit.Preds
		}
		return b.Preds
	}
	pred := func(b *ssa.Block) []*ssa.Block {
		if b == exit {
			return nil
		}
		if len(b.Succs) == 0 {
			return []*ssa.Block{exit}
		}
		return b.Succs
	}
	t := ssa.DominatorsOf(exit, succ, pred)
	out := map[*ssa.Block]*ssa.Block{}
	for b, d := range t.Idom {
		if b != exit && d != exit {
			out[b] = d
		}
	}
	return out
}

// findLoops finds natural loops: a back edge u -> h where h dominates u
// makes h a header, and the body is everything reaching u without passing
// h.
func (s *structurer) findLoops() {
	s.loops = map[*ssa.Block]*loop{}
	for _, b := range s.dom.Order {
		for _, h := range b.Succs {
			if !s.dom.Dominates(h, b) {
				continue
			}
			l := s.loops[h]
			if l == nil {
				l = &loop{header: h, body: map[*ssa.Block]bool{h: true}}
				s.loops[h] = l
			}
			work := []*ssa.Block{b}
			for len(work) > 0 {
				x := work[len(work)-1]
				work = work[:len(work)-1]
				if l.body[x] {
					continue
				}
				l.body[x] = true
				work = append(work, x.Preds...)
			}
		}
	}
	for h, l := range s.loops {
		// The follow is the header's post-dominator when it lies outside
		// the loop, else the only block the loop exits to.
		if p := s.ipdom[h]; p != nil && !l.body[p] {
			l.follow = p
			continue
		}
		var exits []*ssa.Block
		seen := map[*ssa.Block]bool{}
		for _, b := range s.dom.Order {
			if !l.body[b] {
				continue
			}
			for _, x := range b.Succs {
				if !l.body[x] && !seen[x] {
					seen[x] = true
					exits = append(exits, x)
				}
			}
		}
		if len(exits) == 1 {
			l.follow = exits[0]
		}
	}
}

func (s *structurer) jump(target *ssa.Block) Node {
	s.labels[target] = true
	return Goto{Target: target}
}

// seq places blocks from b on until control reaches c.follow, leaves the
// current loop, or ends.
func (s *structurer) seq(b *ssa.Block, c ctx) Seq {
	var out Seq
	for b != nil {
		if b == c.follow {
			return out
		}
		if l := c.loop; l != nil && b == l.header && s.placed[b] {
			return append(out, Continue{})
		}
		if l := c.loop; l != nil && b == l.follow {
			if c.inSwitch {
				return append(out, s.jump(b))
			}
			return append(out, Break{})
		}
		if s.placed[b] {
			return append(out, s.jump(b))
		}
		if l := s.loops[b]; l != nil && !s.entered[b] {
			s.entered[b] = true
			body := s.seq(b, ctx{loop: l})
			out = append(out, Loop{Body: body})
			b = l.follow
			continue
		}
		s.placed[b] = true
		out = append(out, Block{B: b})
		switch b.Kind {
		case ssa.BlockReturn:
			return append(out, Return{B: b})
		case ssa.BlockStop:
			return append(out, Stop{B: b})
		case ssa.BlockPlain:
			b = b.Succs[0]
		case ssa.BlockIf:
			m := s.merge(b, c)
			inner := ctx{follow: m, loop: c.loop, inSwitch: c.inSwitch}
			then := s.seq(b.Succs[1], inner)
			els := s.seq(b.Succs[0], inner)
			out = append(out, If{B: b, Then: then, Else: els})
			b = m
		case ssa.BlockSwitch:
			m := s.merge(b, c)
			inner := ctx{follow: m, loop: c.loop, inSwitch: c.loop != nil}
			sw := Switch{B: b}
			for _, t := range b.Succs {
				body := s.seq(t, inner)
				if !ends(body) {
					body = append(body, Break{})
				}
				sw.Cases = append(sw.Cases, Case{Target: t, Body: body})
			}
			out = append(out, sw)
			b = m
		default:
			return out
		}
	}
	return out
}

// merge is where the arms of a branch at b meet: b's immediate post-
// dominator, unless that lies outside the loop being structured (then the
// arms end in break, continue or return).
func (s *structurer) merge(b *ssa.Block, c ctx) *ssa.Block {
	m := s.ipdom[b]
	if m == nil {
		return nil
	}
	if c.loop != nil && !c.loop.body[m] {
		return nil
	}
	return m
}

// ends reports whether control never falls off the end of seq.
func ends(seq Seq) bool {
	if len(seq) == 0 {
		return false
	}
	switch n := seq[len(seq)-1].(type) {
	case Return, Stop, Goto, Break, Continue:
		return true
	case If:
		return ends(n.Then) && ends(n.Else)
	case Loop:
		return !breaks(n.Body)
	}
	return false
}

// breaks reports whether a break inside seq leaves the loop holding it.
func breaks(seq Seq) bool {
	for _, n := range seq {
		switch n := n.(type) {
		case Break:
			return true
		case If:
			if breaks(n.Then) || breaks(n.Else) {
				return true
			}
		case Seq:
			if breaks(n) {
				return true
			}
		}
	}
	return false
}
