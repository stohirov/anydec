package analysis

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/loader"
)

// Lifter decodes the instruction at an address and lifts it to IR. An
// instruction that decodes but cannot be lifted comes back with an error
// and, when it decoded, a non-nil Insn without ops.
type Lifter interface {
	Lift(addr uint64) (*ir.Insn, error)
}

// Options tunes function discovery.
type Options struct {
	// Sweep makes discovery look for functions in executable bytes that
	// no known function reaches (see sweep).
	Sweep bool
	// Prologue reports whether an instruction typically starts a function;
	// the sweep tries those inside gaps. May be nil.
	Prologue func(*ir.Insn) bool
	// Alignment is the instruction alignment the sweep steps by.
	Alignment int
	// MaxJumpCases bounds the jump tables discovery accepts (default 1024).
	MaxJumpCases int
}

var errNotCode = errors.New("not in executable code")

// Discover finds the functions of p and builds their control-flow graphs.
// Seeds are the entry point and function symbols; from each, discovery
// follows control flow, starts new functions at call targets, resolves jump
// tables, and repeats until nothing new turns up. Functions come back
// sorted by entry address.
func Discover(p *loader.Program, l Lifter, opt Options) []*ir.Function {
	if opt.MaxJumpCases <= 0 {
		opt.MaxJumpCases = 1024
	}
	d := &discoverer{
		prog:    p,
		lift:    l,
		opt:     opt,
		insns:   map[uint64]*ir.Insn{},
		errs:    map[uint64]error{},
		entries: map[uint64]bool{},
		tables:  map[uint64][]ir.JumpCase{},
		tried:   map[uint64]bool{},
		funcs:   map[uint64]*ir.Function{},
	}
	if p.HasEntry {
		d.addEntry(p.Entry)
	}
	for _, s := range p.Symbols {
		if s.Kind == loader.SymFunction {
			d.addEntry(s.Addr)
		}
	}
	d.run()
	if opt.Sweep {
		d.sweep()
	}

	out := make([]*ir.Function, 0, len(d.funcs))
	for _, fn := range d.funcs {
		out = append(out, fn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Entry < out[j].Entry })
	return out
}

type discoverer struct {
	prog    *loader.Program
	lift    Lifter
	opt     Options
	insns   map[uint64]*ir.Insn
	errs    map[uint64]error
	entries map[uint64]bool
	pending []uint64
	tables  map[uint64][]ir.JumpCase // resolved indirect jumps
	tried   map[uint64]bool          // indirect jumps resolution gave up on
	funcs   map[uint64]*ir.Function
}

func (d *discoverer) isCode(addr uint64) bool {
	s := d.prog.Segment(addr)
	return s != nil && s.Perm&loader.PermX != 0 && d.prog.ModeAt(addr) != loader.ModeData
}

func (d *discoverer) addEntry(addr uint64) {
	if !d.entries[addr] && d.isCode(addr) {
		d.entries[addr] = true
		d.pending = append(d.pending, addr)
	}
}

// run builds every pending function, then rebuilds functions that grew
// over an entry found later, until no new entries appear.
func (d *discoverer) run() {
	for len(d.pending) > 0 {
		fresh := d.pending
		d.pending = nil
		for _, e := range fresh {
			d.funcs[e] = d.build(e)
		}
		isFresh := map[uint64]bool{}
		for _, e := range fresh {
			isFresh[e] = true
		}
		for e, fn := range d.funcs {
			if isFresh[e] {
				continue
			}
			for _, in := range fn.Insns {
				if in.Addr != e && isFresh[in.Addr] {
					d.funcs[e] = d.build(e)
					break
				}
			}
		}
	}
}

// insn lifts the instruction at addr once and caches the result.
func (d *discoverer) insn(addr uint64) (*ir.Insn, error) {
	if in, ok := d.insns[addr]; ok {
		return in, d.errs[addr]
	}
	if err, ok := d.errs[addr]; ok {
		return nil, err
	}
	if !d.isCode(addr) {
		return nil, errNotCode
	}
	in, err := d.lift.Lift(addr)
	if in != nil {
		d.insns[addr] = in
	}
	if err != nil {
		d.errs[addr] = err
	}
	return in, err
}

// intra reports whether a branch from the function at entry to target
// stays inside it. Branches to other functions are tail calls.
func (d *discoverer) intra(entry, target uint64) bool {
	return target == entry || (!d.entries[target] && d.isCode(target))
}

func (d *discoverer) name(entry uint64) string {
	if s, ok := d.prog.Symbol(entry); ok {
		return s.Name
	}
	return fmt.Sprintf("sub_%x", entry)
}

// node is one op of one instruction. Index len(Ops) stands for the end of
// the instruction, where control falls through to the next one.
type node struct {
	addr uint64
	idx  int
}

// edge is where control goes after an op: a node in this function, or a
// branch that leaves it (exit, with the ram target in addr).
type edge struct {
	to   node
	exit bool
	addr uint64
}

// opSucc returns the control successors of op i of in, with "falls
// through" as node {in.Addr, len(in.Ops)}.
func (d *discoverer) opSucc(fn *ir.Function, in *ir.Insn, i int) []edge {
	op := in.Ops[i]
	local := func(j int) edge { return edge{to: node{in.Addr, j}} }
	target := func(v ir.Varnode) edge {
		if v.Space == ir.SpaceConst {
			return local(i + int(ir.SignExtend(v.Offset, int(v.Size))))
		}
		if v.Space == ir.SpaceRAM && d.intra(fn.Entry, v.Offset) {
			return edge{to: node{v.Offset, 0}}
		}
		return edge{exit: true, addr: v.Offset}
	}
	switch op.Code {
	case ir.OpBranch:
		return []edge{target(op.In[0])}
	case ir.OpCBranch:
		return []edge{local(i + 1), target(op.In[0])}
	case ir.OpBranchInd:
		var out []edge
		seen := map[uint64]bool{}
		for _, c := range d.tables[in.Addr] {
			if !seen[c.Target] {
				seen[c.Target] = true
				out = append(out, edge{to: node{c.Target, 0}})
			}
		}
		return out
	case ir.OpReturn:
		return nil
	}
	return []edge{local(i + 1)}
}

func isTerminator(c ir.Opcode) bool {
	switch c {
	case ir.OpBranch, ir.OpCBranch, ir.OpBranchInd, ir.OpReturn:
		return true
	}
	return false
}

// build discovers the instructions of the function at entry and its CFG,
// resolving jump tables until none is left to try.
func (d *discoverer) build(entry uint64) *ir.Function {
	for {
		fn := d.buildOnce(entry)
		retry := false
		for _, b := range fn.Blocks {
			last := b.Ops[len(b.Ops)-1]
			if last.Code != ir.OpBranchInd || d.tried[last.Origin] {
				continue
			}
			if _, ok := d.tables[last.Origin]; ok {
				continue
			}
			d.tried[last.Origin] = true
			if cases := d.resolveJump(fn, b); cases != nil {
				d.tables[last.Origin] = cases
				retry = true
			}
		}
		if !retry {
			for _, c := range fn.Calls {
				d.addEntry(c)
			}
			return fn
		}
	}
}

func (d *discoverer) buildOnce(entry uint64) *ir.Function {
	fn := &ir.Function{Entry: entry, Name: d.name(entry)}
	warn := func(addr uint64, format string, args ...any) {
		fn.Warnings = append(fn.Warnings, ir.Warning{Addr: addr, Msg: fmt.Sprintf(format, args...)})
	}

	// Collect the instructions control can reach, following fall-through
	// first so that context set by one instruction (a Thumb IT block)
	// reaches the next before it decodes.
	insns := map[uint64]*ir.Insn{}
	reach := map[uint64][]bool{} // reachable ops per instruction
	calls := map[uint64]bool{}
	work := []uint64{entry}
	for len(work) > 0 {
		a := work[len(work)-1]
		work = work[:len(work)-1]
		for insns[a] == nil {
			in, err := d.insn(a)
			if in == nil {
				warn(a, "flow reaches undecodable bytes: %v", err)
				break
			}
			insns[a] = in
			if err != nil {
				warn(a, "%v", err)
				break
			}
			r, falls := d.reachable(fn, in)
			reach[a] = r
			for i, op := range in.Ops {
				if !r[i] {
					continue
				}
				if op.Code == ir.OpCall && op.In[0].Space == ir.SpaceRAM {
					calls[op.In[0].Offset] = true
				}
				for _, e := range d.opSucc(fn, in, i) {
					switch {
					case e.exit:
						calls[e.addr] = true
					case e.to.addr != a:
						work = append(work, e.to.addr)
					}
				}
			}
			if !falls {
				break
			}
			a += uint64(in.Length)
		}
	}
	for a := range insns {
		fn.Insns = append(fn.Insns, insns[a])
	}
	sort.Slice(fn.Insns, func(i, j int) bool { return fn.Insns[i].Addr < fn.Insns[j].Addr })
	for c := range calls {
		fn.Calls = append(fn.Calls, c)
	}
	sort.Slice(fn.Calls, func(i, j int) bool { return fn.Calls[i] < fn.Calls[j] })

	// resolve maps a node to the first op control reaches there: the end of
	// an instruction is the start of the next, and instructions without
	// ops pass control on.
	resolve := func(n node) (node, bool) {
		for range len(insns) + 1 {
			in := insns[n.addr]
			if in == nil || d.errs[n.addr] != nil {
				return node{}, false
			}
			if n.idx < len(in.Ops) {
				return n, n.idx >= 0
			}
			n = node{n.addr + uint64(in.Length), 0}
		}
		return node{}, false
	}

	// Successor edges per reachable op, and predecessor counts.
	type opInfo struct {
		succ  []edge
		npred int
	}
	info := map[node]*opInfo{}
	var order []node
	for _, in := range fn.Insns {
		for i := range in.Ops {
			if reach[in.Addr] != nil && reach[in.Addr][i] {
				n := node{in.Addr, i}
				info[n] = &opInfo{}
				order = append(order, n)
			}
		}
	}
	for _, n := range order {
		in := insns[n.addr]
		for _, e := range d.opSucc(fn, in, n.idx) {
			if !e.exit {
				to, ok := resolve(e.to)
				if !ok {
					if e.to.addr != n.addr || e.to.idx != len(in.Ops) {
						warn(n.addr, "branch to %#x leaves decoded code", e.to.addr)
					}
					continue
				}
				e.to = to
				info[to].npred++
			}
			info[n].succ = append(info[n].succ, e)
		}
	}
	start, ok := resolve(node{entry, 0})
	if !ok {
		warn(entry, "function has no code")
		return fn
	}
	info[start].npred++ // the function entry

	// Blocks are maximal chains of ops where each op has one successor and
	// the next has one predecessor.
	isLeader := map[node]bool{}
	for _, n := range order {
		if info[n].npred != 1 || n == start {
			isLeader[n] = true
		}
		op := insns[n.addr].Ops[n.idx]
		if isTerminator(op.Code) || len(info[n].succ) != 1 {
			for _, e := range info[n].succ {
				if !e.exit {
					isLeader[e.to] = true
				}
			}
		}
	}
	blockOf := map[node]*ir.Block{}
	var blocks []*ir.Block
	lastNode := map[*ir.Block]node{}
	for _, n := range order {
		if !isLeader[n] {
			continue
		}
		b := &ir.Block{Start: n.addr}
		cur := n
		for {
			blockOf[cur] = b
			b.Ops = append(b.Ops, insns[cur.addr].Ops[cur.idx])
			s := info[cur].succ
			if isTerminator(b.Ops[len(b.Ops)-1].Code) || len(s) != 1 || s[0].exit || isLeader[s[0].to] {
				break
			}
			cur = s[0].to
		}
		lastNode[b] = cur
		blocks = append(blocks, b)
	}

	// Edges. A conditional branch that leaves the function gets a block of
	// its own holding that branch, so CBRANCH always has two successors.
	for _, b := range blocks {
		n := lastNode[b]
		for _, e := range info[n].succ {
			var to *ir.Block
			if e.exit {
				op := insns[n.addr].Ops[n.idx]
				if op.Code != ir.OpCBranch {
					continue
				}
				to = &ir.Block{Start: n.addr, Ops: []ir.Op{{
					Code:   ir.OpBranch,
					In:     []ir.Varnode{op.In[0]},
					Origin: op.Origin,
				}}}
				blocks = append(blocks, to)
			} else {
				to = blockOf[e.to]
			}
			b.Succ = append(b.Succ, to)
			to.Pred = append(to.Pred, b)
		}
	}
	entryBlock := blockOf[start]
	sort.SliceStable(blocks, func(i, j int) bool {
		if (blocks[i] == entryBlock) != (blocks[j] == entryBlock) {
			return blocks[i] == entryBlock
		}
		return blocks[i].Start < blocks[j].Start
	})
	fn.Blocks = blocks

	for _, b := range blocks {
		last := b.Ops[len(b.Ops)-1]
		if last.Code != ir.OpBranchInd {
			continue
		}
		if cases, ok := d.tables[last.Origin]; ok {
			fn.JumpTables = append(fn.JumpTables, ir.JumpTable{Addr: last.Origin, Cases: cases})
		} else {
			fn.Unresolved = append(fn.Unresolved, last.Origin)
		}
	}
	return fn
}

// reachable returns which ops of in run when control enters at op 0, and
// whether control can reach the end of the instruction.
func (d *discoverer) reachable(fn *ir.Function, in *ir.Insn) ([]bool, bool) {
	r := make([]bool, len(in.Ops))
	falls := len(in.Ops) == 0
	work := []int{0}
	for len(work) > 0 {
		i := work[len(work)-1]
		work = work[:len(work)-1]
		if i == len(in.Ops) {
			falls = true
			continue
		}
		if i < 0 || i > len(in.Ops) || r[i] {
			continue
		}
		r[i] = true
		for _, e := range d.opSucc(fn, in, i) {
			if !e.exit && e.to.addr == in.Addr {
				work = append(work, e.to.idx)
			}
		}
	}
	return r, falls
}

// sweep finds functions only reached indirectly, or not at all, by
// looking at the executable bytes no function covers. Compilers lay
// functions out back to back, so the first instruction of each gap, after
// padding, is a candidate; so is every prologue inside a gap. A candidate
// becomes a function when flow from it decodes without warnings and stays
// inside its gap. Gaps are recomputed after each new function.
func (d *discoverer) sweep() {
	align := uint64(max(d.opt.Alignment, 1))
	for {
		found := false
		for _, g := range d.gaps() {
			start, ok := d.skipPadding(g.start, g.end)
			if !ok {
				continue
			}
			if d.plausible(start, g.limit) {
				d.addEntry(start)
				found = true
				break
			}
			if d.opt.Prologue == nil {
				continue
			}
			for a := start + align; a < g.end && !found; a += align {
				if in, err := d.insn(a); err == nil && d.opt.Prologue(in) && d.plausible(a, g.limit) {
					d.addEntry(a)
					found = true
				}
			}
			if found {
				break
			}
		}
		if !found {
			return
		}
		d.run()
	}
}

// gap is a run [start, end) of executable, non-data bytes no function
// covers. Code starting there may extend to limit, past data islands, up
// to the next covered byte.
type gap struct{ start, end, limit uint64 }

func (d *discoverer) gaps() []gap {
	type span struct{ start, end uint64 }
	var covered []span
	for _, fn := range d.funcs {
		for _, in := range fn.Insns {
			covered = append(covered, span{in.Addr, in.Addr + uint64(in.Length)})
		}
	}
	sort.Slice(covered, func(i, j int) bool { return covered[i].start < covered[j].start })
	var out []gap
	for _, seg := range d.prog.Segments {
		if seg.Perm&loader.PermX == 0 {
			continue
		}
		i := sort.Search(len(covered), func(i int) bool { return covered[i].end > seg.Addr })
		for a := seg.Addr; a < seg.End(); {
			for i < len(covered) && covered[i].end <= a {
				i++
			}
			end := seg.End()
			if i < len(covered) && covered[i].start <= a {
				a = covered[i].end
				continue
			}
			if i < len(covered) && covered[i].start < end {
				end = covered[i].start
			}
			// Split at mode changes, dropping data.
			for a < end {
				next := min(end, d.nextMode(a))
				if d.prog.ModeAt(a) != loader.ModeData {
					out = append(out, gap{a, next, end})
				}
				a = next
			}
		}
	}
	return out
}

func (d *discoverer) nextMode(addr uint64) uint64 {
	i := sort.Search(len(d.prog.Modes), func(i int) bool { return d.prog.Modes[i].Addr > addr })
	if i < len(d.prog.Modes) {
		return d.prog.Modes[i].Addr
	}
	return ^uint64(0)
}

// skipPadding returns the first address in [start, end) that is not
// padding: instructions without semantics, zero fill, or traps.
func (d *discoverer) skipPadding(start, end uint64) (uint64, bool) {
	align := uint64(max(d.opt.Alignment, 1))
	for a := start; a < end; {
		in, err := d.insn(a)
		if in == nil {
			if b, rerr := d.prog.Read(a, int(align)); rerr == nil && allZero(b) {
				a += align
				continue
			}
			return 0, false
		}
		if err == nil && len(in.Ops) > 0 && !allZero(in.Bytes) && !padding[mnemonic(in.Text)] {
			return a, true
		}
		a += uint64(in.Length)
	}
	return 0, false
}

// padding lists mnemonics compilers fill between functions with: no-ops
// (some, like x86's long NOP, still compute an address in P-code) and
// traps.
var padding = map[string]bool{"nop": true, "int3": true, "ud2": true, "udf": true}

func mnemonic(text string) string {
	m, _, _ := strings.Cut(text, " ")
	return strings.ToLower(m)
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return len(b) > 0
}

// plausible reports whether a function starting at start decodes cleanly
// and stays inside [start, end).
func (d *discoverer) plausible(start, end uint64) bool {
	fn := d.buildOnce(start)
	if len(fn.Warnings) > 0 || len(fn.Blocks) == 0 {
		return false
	}
	for _, in := range fn.Insns {
		if in.Addr < start || in.Addr+uint64(in.Length) > end {
			return false
		}
	}
	return true
}
