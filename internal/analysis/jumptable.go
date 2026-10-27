package analysis

import (
	"math/rand/v2"
	"sort"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/loader"
)

// Jump tables are resolved without ISA-specific patterns.
//
// First, symbolic execution: starting at a dominator of the jumping block,
// the acyclic region of blocks leading to it runs symbolically. Every value
// becomes an expression over leaves, the values live at the region's start.
// Stores are forwarded to later loads, and loads from read-only memory read
// the image. Along the way each block gets a path condition, the
// expression under which control reaches it. Where paths merge, values
// that differ become selects on those conditions, so the analysis stays
// path-sensitive across conditional instructions and diamonds.
//
// Then enumeration: for each leaf in turn, and then for the low parts of
// leaves, discovery tries the candidate's values, keeps those for which
// the jump's path condition holds, and evaluates the target for each. A
// candidate is the switch variable when the feasible values are bounded,
// every target is code, and two different assignments of the other leaves
// give the same answer. Those assignments are drawn at random until they
// satisfy the conjuncts of the path condition that do not involve the
// candidate (a loop bound, say), so the paths they describe can reach the
// jump. Anything else leaves the jump
// unresolved: targets are never guessed.

const (
	maxRegionBlocks = 64
	maxDominatorUp  = 16
)

type exprKind uint8

const (
	exConst  exprKind = iota
	exLeaf            // a value live at the start of the region
	exLoad            // memory the region did not write
	exOp              // an IR op over args
	exSelect          // args[0] ? args[1] : args[2]
)

type expr struct {
	id    int
	kind  exprKind
	op    ir.Opcode
	size  int
	val   uint64     // exConst
	space ir.SpaceID // exLoad
	args  []*expr
	leaf  int // exLeaf and exLoad: index of the value in an env
}

type binding struct {
	v ir.Varnode
	e *expr
}

// store is a write the region made; guard, when set, is the condition
// under which it happened.
type store struct {
	space ir.SpaceID
	addr  *expr
	size  int
	val   *expr
	guard *expr
}

// state is the symbolic machine state on entry to or exit from a block.
type state struct {
	regs   []binding
	stores []store
	pc     *expr // path condition
	// clobbered is set after a call: registers no longer hold the
	// region's initial values.
	clobbered bool
}

func (st *state) clone() *state {
	c := *st
	c.regs = append([]binding(nil), st.regs...)
	c.stores = append([]store(nil), st.stores...)
	return &c
}

// env assigns values to leaves and memoizes evaluation. over, when set,
// forces one node's value.
type env struct {
	vals    []uint64
	memo    []uint64
	stamp   []uint32
	gen     uint32
	over    *expr
	overVal uint64
}

type symbolic struct {
	prog    *loader.Program
	big     bool
	nodes   []*expr
	nleaf   int
	initial map[ir.Varnode]*expr // leaves for registers unwritten in the region
	probes  [2]*env              // random values for alias checks
	rng     *rand.Rand
	one     *expr
}

func newSymbolic(p *loader.Program, seed uint64) *symbolic {
	s := &symbolic{
		prog:    p,
		big:     p.BigEndian,
		initial: map[ir.Varnode]*expr{},
		probes:  [2]*env{{}, {}},
		rng:     rand.New(rand.NewPCG(seed, 0x6a756d70)),
	}
	s.one = s.constant(1, 1)
	return s
}

func (s *symbolic) node(e *expr) *expr {
	e.id = len(s.nodes)
	s.nodes = append(s.nodes, e)
	return e
}

func (s *symbolic) constant(v uint64, size int) *expr {
	return s.node(&expr{kind: exConst, val: v & ir.Mask(size), size: size})
}

func (s *symbolic) newLeaf(kind exprKind, size int) *expr {
	e := s.node(&expr{kind: kind, size: size, leaf: s.nleaf})
	s.nleaf++
	for _, p := range s.probes {
		p.vals = append(p.vals, s.rng.Uint64()&ir.Mask(size))
	}
	return e
}

// eval computes e under en; ok is false when some op cannot be evaluated.
func (s *symbolic) eval(e *expr, en *env) (uint64, bool) {
	if len(en.memo) < len(s.nodes) {
		en.memo = append(en.memo, make([]uint64, len(s.nodes)-len(en.memo))...)
		en.stamp = append(en.stamp, make([]uint32, len(s.nodes)-len(en.stamp))...)
	}
	if en.stamp[e.id] == en.gen {
		return en.memo[e.id], true
	}
	var v uint64
	switch {
	case e == en.over:
		v = en.overVal & ir.Mask(e.size)
	case e.kind == exConst:
		v = e.val
	case e.kind == exLeaf:
		v = en.vals[e.leaf]
	case e.kind == exLoad:
		a, ok := s.eval(e.args[0], en)
		if !ok {
			return 0, false
		}
		if b, ok := s.readOnly(e.space, a, e.size); ok {
			v = b
		} else {
			v = en.vals[e.leaf]
		}
	case e.kind == exSelect:
		c, ok := s.eval(e.args[0], en)
		if !ok {
			return 0, false
		}
		pick := e.args[2]
		if c&1 != 0 {
			pick = e.args[1]
		}
		if v, ok = s.eval(pick, en); !ok {
			return 0, false
		}
	default:
		in := make([]uint64, len(e.args))
		sizes := make([]int, len(e.args))
		for i, a := range e.args {
			x, ok := s.eval(a, en)
			if !ok {
				return 0, false
			}
			in[i], sizes[i] = x, a.size
		}
		x, err := ir.Eval(e.op, e.size, in, sizes)
		if err != nil {
			return 0, false
		}
		v = x
	}
	en.memo[e.id], en.stamp[e.id] = v, en.gen
	return v, true
}

// readOnly reads size bytes of initialized, non-writable memory.
func (s *symbolic) readOnly(space ir.SpaceID, addr uint64, size int) (uint64, bool) {
	if space != ir.SpaceRAM || size > 8 {
		return 0, false
	}
	seg := s.prog.Segment(addr)
	if seg == nil || seg.Perm&loader.PermW != 0 || seg.Name == loader.ExternalSegment || addr+uint64(size) > seg.End() {
		return 0, false
	}
	b := seg.Data[addr-seg.Addr:][:size]
	var v uint64
	for i := range size {
		if s.big {
			v = v<<8 | uint64(b[i])
		} else {
			v |= uint64(b[i]) << (8 * i)
		}
	}
	return v, true
}

// sameAddr reports whether two address expressions agree under both
// probe assignments.
func (s *symbolic) sameAddr(a, b *expr) bool {
	for _, p := range s.probes {
		p.gen++
		x, ok1 := s.eval(a, p)
		y, ok2 := s.eval(b, p)
		if !ok1 || !ok2 || x != y {
			return false
		}
	}
	return true
}

// read returns the expression for varnode v in st.
func (s *symbolic) read(st *state, v ir.Varnode) *expr {
	switch v.Space {
	case ir.SpaceConst:
		return s.constant(v.Offset, int(v.Size))
	case ir.SpaceRAM:
		return s.load(st, ir.SpaceRAM, s.constant(v.Offset, 8), int(v.Size))
	}
	for i := len(st.regs) - 1; i >= 0; i-- {
		b := st.regs[i]
		if b.v.Space != v.Space {
			continue
		}
		if b.v == v {
			return b.e
		}
		end, bend := v.Offset+uint64(v.Size), b.v.Offset+uint64(b.v.Size)
		if v.Offset >= b.v.Offset && end <= bend {
			shift := v.Offset - b.v.Offset
			if s.big {
				shift = bend - end
			}
			return s.op(ir.OpSubpiece, int(v.Size), b.e, s.constant(shift, 4))
		}
		if v.Offset < bend && b.v.Offset < end {
			break // partly written: not tracked
		}
	}
	if !st.clobbered {
		if e := s.initial[v]; e != nil {
			return e
		}
	}
	e := s.newLeaf(exLeaf, int(v.Size))
	if st.clobbered {
		st.regs = append(st.regs, binding{v, e})
	} else {
		s.initial[v] = e
	}
	return e
}

func (s *symbolic) write(st *state, v ir.Varnode, e *expr) {
	if v.Space == ir.SpaceRAM {
		st.stores = append(st.stores, store{ir.SpaceRAM, s.constant(v.Offset, 8), int(v.Size), e, nil})
		return
	}
	// Drop bindings this write overlaps, so stale values never resurface.
	kept := st.regs[:0:0]
	end := v.Offset + uint64(v.Size)
	for _, b := range st.regs {
		if b.v.Space == v.Space && b.v.Offset < end && v.Offset < b.v.Offset+uint64(b.v.Size) {
			continue
		}
		kept = append(kept, b)
	}
	st.regs = append(kept, binding{v, e})
}

// load returns the value at addr: the latest matching store, selected on
// its guard when it was conditional, or memory as the region found it.
func (s *symbolic) load(st *state, space ir.SpaceID, addr *expr, size int) *expr {
	return s.loadFrom(st.stores, space, addr, size)
}

func (s *symbolic) loadFrom(stores []store, space ir.SpaceID, addr *expr, size int) *expr {
	for i := len(stores) - 1; i >= 0; i-- {
		w := stores[i]
		if w.space != space || w.size != size || !s.sameAddr(w.addr, addr) {
			continue
		}
		if w.guard == nil {
			return w.val
		}
		return s.selectOn(w.guard, w.val, s.loadFrom(stores[:i], space, addr, size))
	}
	e := s.newLeaf(exLoad, size)
	e.space, e.args = space, []*expr{addr}
	return e
}

func (s *symbolic) selectOn(c, a, b *expr) *expr {
	if a == b {
		return a
	}
	return s.node(&expr{kind: exSelect, size: a.size, args: []*expr{c, a, b}})
}

// op builds an op expression, folding constants.
func (s *symbolic) op(code ir.Opcode, size int, args ...*expr) *expr {
	allConst := true
	for _, a := range args {
		allConst = allConst && a.kind == exConst
	}
	if allConst {
		in := make([]uint64, len(args))
		sizes := make([]int, len(args))
		for i, a := range args {
			in[i], sizes[i] = a.val, a.size
		}
		if v, err := ir.Eval(code, size, in, sizes); err == nil {
			return s.constant(v, size)
		}
	}
	return s.node(&expr{kind: exOp, op: code, size: size, args: args})
}

func (s *symbolic) and(a, b *expr) *expr {
	switch {
	case a == s.one:
		return b
	case b == s.one:
		return a
	}
	return s.op(ir.OpBoolAnd, 1, a, b)
}

func (s *symbolic) or(a, b *expr) *expr {
	if a == s.one || b == s.one {
		return s.one
	}
	return s.op(ir.OpBoolOr, 1, a, b)
}

// exec runs one op symbolically.
func (s *symbolic) exec(st *state, op ir.Op) {
	switch op.Code {
	case ir.OpLoad:
		addr := s.read(st, op.In[1])
		if ir.SpaceID(op.In[0].Offset) == ir.SpaceConst {
			// Loading from the constant space yields the address itself.
			s.write(st, *op.Out, s.op(ir.OpIntZExt, int(op.Out.Size), addr))
			return
		}
		s.write(st, *op.Out, s.load(st, ir.SpaceID(op.In[0].Offset), addr, int(op.Out.Size)))
	case ir.OpStore:
		st.stores = append(st.stores, store{ir.SpaceID(op.In[0].Offset), s.read(st, op.In[1]), int(op.In[2].Size), s.read(st, op.In[2]), nil})
	case ir.OpCall, ir.OpCallInd:
		// A call may change any register or memory.
		st.regs, st.stores, st.clobbered = nil, nil, true
	case ir.OpBranch, ir.OpCBranch, ir.OpBranchInd, ir.OpReturn:
	default:
		if op.Out == nil {
			return
		}
		switch op.Code {
		case ir.OpCallOther, ir.OpPhi, ir.OpIndirect, ir.OpNew, ir.OpCPoolRef, ir.OpSegmentOp:
			s.write(st, *op.Out, s.newLeaf(exLeaf, int(op.Out.Size)))
			return
		}
		args := make([]*expr, len(op.In))
		for i, in := range op.In {
			args[i] = s.read(st, in)
		}
		s.write(st, *op.Out, s.op(op.Code, int(op.Out.Size), args...))
	}
}

// merge combines the exit states of a block's predecessors, each already
// carrying the condition of its edge into the block.
func (s *symbolic) merge(in []*state) *state {
	if len(in) == 1 {
		return in[0]
	}
	out := &state{pc: in[0].pc}
	for _, st := range in[1:] {
		out.pc = s.or(out.pc, st.pc)
		out.clobbered = out.clobbered || st.clobbered
	}
	out.clobbered = out.clobbered || in[0].clobbered
	// Registers: every varnode bound in any predecessor, largest first, is
	// bound to the select of its values on the predecessors' conditions.
	var keys []ir.Varnode
	seen := map[ir.Varnode]bool{}
	for _, st := range in {
		for _, b := range st.regs {
			if !seen[b.v] {
				seen[b.v] = true
				keys = append(keys, b.v)
			}
		}
	}
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].Size > keys[j].Size })
	for _, k := range keys {
		vals := make([]*expr, len(in))
		for i, st := range in {
			vals[i] = s.read(st, k)
		}
		v := vals[len(vals)-1]
		for i := len(vals) - 2; i >= 0; i-- {
			v = s.selectOn(in[i].pc, vals[i], v)
		}
		s.write(out, k, v)
	}
	// Memory: the common prefix of stores, then each predecessor's own
	// stores guarded by its condition.
	common := len(in[0].stores)
	for _, st := range in[1:] {
		n := 0
		for n < common && n < len(st.stores) && st.stores[n] == in[0].stores[n] {
			n++
		}
		common = n
	}
	out.stores = append([]store(nil), in[0].stores[:common]...)
	for _, st := range in {
		for _, w := range st.stores[common:] {
			g := st.pc
			if w.guard != nil {
				g = s.and(g, w.guard)
			}
			w.guard = g
			out.stores = append(out.stores, w)
		}
	}
	return out
}

// region returns the blocks on paths from start to target that do not
// pass through start again, in topological order, or nil if those paths
// form a cycle or the region is too big.
func region(start, target *ir.Block) []*ir.Block {
	// Blocks that reach target without passing through start.
	reaches := map[*ir.Block]bool{target: true}
	work := []*ir.Block{target}
	for len(work) > 0 {
		b := work[len(work)-1]
		work = work[:len(work)-1]
		if b == start {
			continue
		}
		for _, p := range b.Pred {
			if !reaches[p] {
				reaches[p] = true
				work = append(work, p)
				if len(reaches) > maxRegionBlocks {
					return nil
				}
			}
		}
	}
	if !reaches[start] {
		return nil
	}
	const (
		unvisited = iota
		active
		done
	)
	mark := map[*ir.Block]int{}
	var order []*ir.Block
	cyclic := false
	var visit func(*ir.Block)
	visit = func(b *ir.Block) {
		mark[b] = active
		if b != target {
			for _, succ := range b.Succ {
				if succ == start {
					cyclic = true
				}
				if !reaches[succ] || succ == start {
					continue
				}
				switch mark[succ] {
				case active:
					cyclic = true
				case unvisited:
					visit(succ)
				}
			}
		}
		mark[b] = done
		order = append(order, b)
	}
	visit(start)
	if cyclic {
		return nil
	}
	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}
	return order
}

// resolveJump tries to prove the targets of the indirect jump ending b.
func (d *discoverer) resolveJump(fn *ir.Function, b *ir.Block) []ir.JumpCase {
	// Use the farthest dominator whose region is acyclic.
	idom := idoms(fn)
	blocks := []*ir.Block{b}
	for start, up := b, 0; up <= maxDominatorUp; up++ {
		if r := region(start, b); r != nil {
			blocks = r
		}
		next := idom[start]
		if next == nil || next == start {
			break
		}
		start = next
	}

	last := b.Ops[len(b.Ops)-1]
	s := newSymbolic(d.prog, last.Origin)
	inRegion := map[*ir.Block]bool{}
	for _, blk := range blocks {
		inRegion[blk] = true
	}
	entering := map[*ir.Block][]*state{}
	var final *state
	for i, blk := range blocks {
		st := &state{pc: s.one}
		if i > 0 {
			st = s.merge(entering[blk]).clone()
		}
		for _, op := range blk.Ops {
			s.exec(st, op)
		}
		if blk == b {
			final = st
			break
		}
		end := blk.Ops[len(blk.Ops)-1]
		two := end.Code == ir.OpCBranch && blk.Succ[0] != blk.Succ[1]
		for k, succ := range blk.Succ {
			if !inRegion[succ] {
				continue
			}
			out := st.clone()
			if two {
				c := s.op(ir.OpIntAnd, 1, s.read(st, end.In[1]), s.one)
				if k == 0 {
					c = s.op(ir.OpBoolNegate, 1, c)
				}
				out.pc = s.and(st.pc, c)
			}
			entering[succ] = append(entering[succ], out)
			if end.Code == ir.OpCBranch && !two {
				break // both edges go to the same block
			}
		}
	}
	if final == nil {
		return nil
	}

	target := s.read(final, last.In[0])
	if target.kind == exConst {
		if d.isCode(target.val) {
			return []ir.JumpCase{{Value: 0, Target: target.val}}
		}
		return nil
	}
	for _, v := range s.candidates() {
		if cases := d.enumerate(s, final.pc, target, v); cases != nil {
			return cases
		}
	}
	return nil
}

// candidates returns the expressions that may be the switch variable:
// every leaf, then the low parts of leaves (a byte switch on a register).
func (s *symbolic) candidates() []*expr {
	var leaves, parts []*expr
	for _, e := range s.nodes {
		switch {
		case e.kind == exLeaf || e.kind == exLoad:
			leaves = append(leaves, e)
		case e.kind == exOp && e.op == ir.OpSubpiece && (e.args[0].kind == exLeaf || e.args[0].kind == exLoad) &&
			e.args[1].kind == exConst && e.args[1].val == 0:
			parts = append(parts, e)
		}
	}
	return append(leaves, parts...)
}

// dependsOn reports whether e involves v.
func dependsOn(e, v *expr, memo map[*expr]bool) bool {
	if r, ok := memo[e]; ok {
		return r
	}
	r := e == v
	for _, a := range e.args {
		r = dependsOn(a, v, memo) || r
	}
	memo[e] = r
	return r
}

// conjuncts splits a path condition at its top-level ANDs.
func conjuncts(e *expr, out []*expr) []*expr {
	if e.kind == exOp && e.op == ir.OpBoolAnd {
		return conjuncts(e.args[1], conjuncts(e.args[0], out))
	}
	return append(out, e)
}

// enumerate tries v as the switch variable.
func (d *discoverer) enumerate(s *symbolic, pc, target, v *expr) []ir.JumpCase {
	size := v.size
	memo := map[*expr]bool{}
	if size == 0 || size > 8 || !dependsOn(target, v, memo) {
		return nil
	}
	var conds, others []*expr
	for _, c := range conjuncts(pc, nil) {
		if dependsOn(c, v, memo) {
			conds = append(conds, c)
		} else {
			others = append(others, c)
		}
	}
	envs := [2]*env{s.context(others), s.context(others)}
	if envs[0] == nil || envs[1] == nil {
		return nil
	}
	// try reports whether value x is feasible and where it jumps; ok is
	// false when the two assignments disagree or evaluation fails.
	try := func(x uint64) (feasible bool, to uint64, ok bool) {
		var res [2]struct {
			f bool
			t uint64
		}
		for i, en := range envs {
			en.gen++
			en.over, en.overVal = v, x
			res[i].f = true
			for _, c := range conds {
				v, ok := s.eval(c, en)
				if !ok {
					return false, 0, false
				}
				if v&1 == 0 {
					res[i].f = false
					break
				}
			}
			if res[i].f {
				t, ok := s.eval(target, en)
				if !ok {
					return false, 0, false
				}
				res[i].t = t
			}
		}
		if res[0] != res[1] {
			return false, 0, false
		}
		return res[0].f, res[0].t, true
	}

	values := map[int64]uint64{}
	seen := map[int64]bool{}
	visit := func(x uint64, edge bool) bool {
		k := ir.SignExtend(x, size)
		if seen[k] {
			return true
		}
		seen[k] = true
		f, t, ok := try(x)
		switch {
		case !ok:
			return false
		case !f:
			return true
		case edge || !d.isCode(t):
			return false
		}
		values[k] = t
		return true
	}
	w := int64(d.opt.MaxJumpCases)
	if ir.Mask(size) < uint64(4*w) {
		// Small variables: try every value.
		for x := uint64(0); x <= ir.Mask(size); x++ {
			if !visit(x, false) {
				return nil
			}
		}
	} else {
		// The feasible set must be bounded: no extreme value may reach the
		// jump, and no window around zero or a constant in the conditions
		// may end on a feasible value.
		half := uint64(1) << (8*size - 1)
		for _, x := range []uint64{half, half - 1, half + 1, ir.Mask(size), ir.Mask(size) - 1} {
			if f, _, ok := try(x); !ok || f {
				return nil
			}
		}
		bases := []int64{0}
		for _, c := range conds {
			bases = appendConsts(bases, c, 8)
		}
		for _, base := range bases {
			for x := base - w; x <= base+w; x++ {
				if !visit(uint64(x), x == base-w || x == base+w) {
					return nil
				}
			}
		}
	}
	if len(values) == 0 || len(values) > d.opt.MaxJumpCases {
		return nil
	}
	cases := make([]ir.JumpCase, 0, len(values))
	for v, t := range values {
		cases = append(cases, ir.JumpCase{Value: v, Target: t})
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].Value < cases[j].Value })
	return cases
}

// context draws random values for every leaf until all of conds hold, or
// returns nil after a bounded number of tries.
func (s *symbolic) context(conds []*expr) *env {
	sizes := make([]int, s.nleaf)
	for _, e := range s.nodes {
		if e.kind == exLeaf || e.kind == exLoad {
			sizes[e.leaf] = e.size
		}
	}
	en := &env{vals: make([]uint64, s.nleaf)}
	for range contextTries {
		for j := range en.vals {
			en.vals[j] = s.rng.Uint64() & ir.Mask(sizes[j])
		}
		en.gen++
		holds := true
		for _, c := range conds {
			if v, ok := s.eval(c, en); !ok || v&1 == 0 {
				holds = false
				break
			}
		}
		if holds {
			return en
		}
	}
	return nil
}

const contextTries = 64

// appendConsts adds the signed constants in e to bases, up to max entries.
func appendConsts(bases []int64, e *expr, max int) []int64 {
	if len(bases) >= max {
		return bases
	}
	if e.kind == exConst {
		v := ir.SignExtend(e.val, e.size)
		for _, b := range bases {
			if b == v {
				return bases
			}
		}
		return append(bases, v)
	}
	for _, a := range e.args {
		bases = appendConsts(bases, a, max)
	}
	return bases
}
