package ssa

import (
	"sort"

	"github.com/stohirov/decompile-anything/internal/ir"
)

// Prototype analysis infers each function's parameters from what it reads
// before writing (liveness at entry) and its results from what it leaves
// in the return registers, then binds every call to its callee's
// prototype. Parameters depend on callees (a register passed straight on
// to a call is a parameter if the callee takes it), so the caller iterates
// InferParams-style facts to a fixed point with PassThrough.

// Param is one parameter: a register, or a stack slot at Offset from the
// stack pointer on entry.
type Param struct {
	Reg    ir.Varnode
	Stack  bool
	Offset int64
	Size   int
	Float  bool
}

// Ret is one register a function returns a value in.
type Ret struct {
	Reg   ir.Varnode
	Size  int
	Float bool
}

// Proto is a function's inferred prototype.
type Proto struct {
	Params []Param
	// Returns holds the result's registers: none for void, two for a
	// value split over a register pair (low part first).
	Returns []Ret
	// Known is false for prototypes guessed at a call site.
	Known bool
}

// RetSize is the size of the returned value in bytes, 0 for void.
func (p *Proto) RetSize() int {
	n := 0
	for _, r := range p.Returns {
		n += r.Size
	}
	return n
}

// Evidence is what a function's own code says about its parameters.
type Evidence struct {
	IntUsed   []bool // per ABI integer parameter register
	FloatUsed []bool
	IntSize   []int // bytes of each register the code uses
	FloatSize []int
	// StackSlots is the number of stack parameter slots read.
	StackSlots int
	// Forwards lists registers passed unchanged to calls, which are
	// parameters when the callee takes them.
	Forwards []Forward
}

// Forward records that the entry value of an argument register reaches a
// call's argument position.
type Forward struct {
	Target uint64 // direct call target; 0 for indirect calls
	Float  bool
	Index  int // in the ABI's register list
}

// users maps every value to the values using it.
func (f *Func) users() map[*Value][]*Value {
	u := map[*Value][]*Value{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for _, a := range v.Args {
				u[a] = append(u[a], v)
			}
		}
	}
	return u
}

// Gather collects parameter evidence from f before stack promotion.
// internal reports call targets whose prototypes analysis infers; calls to
// anything else get the arguments guessArgs picks, so registers they pass
// on are uses.
func (f *Func) Gather(abi *ABI, internal func(target uint64) bool, soft func(c *Value) bool) *Evidence {
	ev := &Evidence{
		IntUsed: make([]bool, len(abi.IntParams)), FloatUsed: make([]bool, len(abi.FloatParams)),
		IntSize: make([]int, len(abi.IntParams)), FloatSize: make([]int, len(abi.FloatParams)),
	}
	users := f.users()
	branch := &Value{Op: ir.OpCBranch} // stands for a block's control use
	for _, blk := range f.Blocks {
		if blk.Control != nil {
			users[blk.Control] = append(users[blk.Control], branch)
		}
	}
	// Returns demand the low bytes of the main return registers, when code
	// set them.
	resultNeed := map[*Value]uint64{}
	for _, blk := range f.Blocks {
		for i, r := range blk.Results {
			if i >= len(f.RetRegs) {
				continue
			}
			reg := f.RetRegs[i]
			main := len(abi.IntReturns) > 0 && reg == abi.IntReturns[0] || len(abi.FloatReturns) > 0 && reg == abi.FloatReturns[0]
			if main && f.defined(r, reg) {
				resultNeed[r] |= ir.Mask(lowWidth(r, f))
			}
		}
	}
	for _, c := range f.Calls() {
		if c.Op == ir.OpCall && internal(c.Aux) {
			continue
		}
		ni, nf := f.guessCounts(c, abi, soft != nil && soft(c))
		c.Call.guessed = map[int]bool{}
		for i := range ni {
			c.Call.guessed[i] = true
		}
		for i := range nf {
			c.Call.guessed[len(abi.IntParams)+i] = true
		}
	}
	d := &demand{users: users, results: resultNeed, memo: map[*Value]uint64{}}
	b := &builder{f: f, arch: f.Arch, vars: f.regAtoms()}
	scan := func(regs []ir.Varnode, used []bool, sizes []int, float bool) {
		for i, r := range regs {
			atoms := b.atoms(lowBytes(r, 8, f.Arch))
			if len(atoms) != 1 {
				continue
			}
			in := f.inputs[atoms[0]]
			if in == nil {
				continue
			}
			for _, u := range users[in] {
				if u.Call == nil || u.Call.NArgs >= 0 {
					continue
				}
				pos := callArgIndex(u, in)
				same := !float && pos == i || float && pos == len(abi.IntParams)+i
				if pos >= 0 && same && u.Op == ir.OpCall {
					ev.Forwards = append(ev.Forwards, Forward{Target: u.Aux, Float: float, Index: i})
				}
			}
			need := d.need(in)
			if need == 0 {
				continue
			}
			used[i] = true
			w := 0
			for need != 0 {
				w++
				need >>= 8
			}
			// A float register may carry a double in the pair it starts.
			limit := int(r.Size)
			if float {
				limit = atoms[0].Size
			}
			sizes[i] = max(sizes[i], min(w, limit, 8))
		}
	}
	scan(abi.IntParams, ev.IntUsed, ev.IntSize, false)
	scan(abi.FloatParams, ev.FloatUsed, ev.FloatSize, true)
	if abi.StackParams {
		for _, a := range f.Frame().Accesses {
			if a.Offset >= abi.StackOffset {
				slot := int((a.Offset-abi.StackOffset+int64(a.Size)-1)/int64(abi.StackAlign)) + 1
				ev.StackSlots = max(ev.StackSlots, slot)
			}
		}
	}
	return ev
}

// callArgIndex returns the candidate register position of x among a
// call's arguments, or -1.
func callArgIndex(c *Value, x *Value) int {
	start := 0
	if c.Op == ir.OpCallInd {
		start = 1
	}
	for i := start; i < len(c.Args)-1; i++ {
		if c.Args[i] == x {
			return i - start
		}
	}
	return -1
}

// regAtoms returns f's register variables by space, sorted by offset.
func (f *Func) regAtoms() map[ir.SpaceID][]*Var {
	seen := map[*Var]bool{}
	out := map[ir.SpaceID][]*Var{}
	add := func(v *Var) {
		if v != nil && v.Space == ir.SpaceRegister && !seen[v] {
			seen[v] = true
			out[v.Space] = append(out[v.Space], v)
		}
	}
	for v := range f.inputs {
		add(v)
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			add(v.Var)
		}
	}
	add(f.SP)
	for _, l := range out {
		sort.Slice(l, func(i, j int) bool { return l[i].Offset < l[j].Offset })
	}
	return out
}

// Params turns evidence into a parameter list: integer registers up to the
// last one used (all of them when stack parameters exist), stack slots,
// then floating-point registers up to the last one used.
func (ev *Evidence) Params(abi *ABI) []Param {
	var out []Param
	last := func(used []bool) int {
		n := 0
		for i, u := range used {
			if u {
				n = i + 1
			}
		}
		return n
	}
	nint := last(ev.IntUsed)
	if ev.StackSlots > 0 {
		nint = len(abi.IntParams)
	}
	for i := range nint {
		size := ev.IntSize[i]
		if size == 0 {
			size = int(abi.IntParams[i].Size)
		}
		out = append(out, Param{Reg: abi.IntParams[i], Size: size})
	}
	for i := range ev.StackSlots {
		out = append(out, Param{Stack: true, Offset: abi.StackOffset + int64(i*abi.StackAlign), Size: abi.StackAlign})
	}
	nf := last(ev.FloatUsed)
	for i := 0; i < nf; i++ {
		r := abi.FloatParams[i]
		size := ev.FloatSize[i]
		if size == 0 {
			size = min(8, int(r.Size))
		}
		if size > int(r.Size) {
			// A double in a pair of single registers (d0 = s0:s1).
			r.Size = uint8(size)
			i++
		}
		out = append(out, Param{Reg: r, Size: size, Float: true})
	}
	return out
}

// PassThrough marks registers ev forwards to callees that take them as
// used; it reports whether anything changed.
func (ev *Evidence) PassThrough(callee func(target uint64) *Evidence) bool {
	changed := false
	for _, fw := range ev.Forwards {
		c := callee(fw.Target)
		if c == nil {
			continue
		}
		used, cused := ev.IntUsed, c.IntUsed
		sizes, csizes := ev.IntSize, c.IntSize
		if fw.Float {
			used, cused, sizes, csizes = ev.FloatUsed, c.FloatUsed, ev.FloatSize, c.FloatSize
		}
		takes := fw.Index < len(cused) && (cused[fw.Index] || (!fw.Float && c.StackSlots > 0))
		if takes && !used[fw.Index] {
			used[fw.Index] = true
			sizes[fw.Index] = max(sizes[fw.Index], csizes[fw.Index])
			changed = true
		}
	}
	return changed
}

// lowBytes is the least significant size bytes of register r.
func lowBytes(r ir.Varnode, size int, arch *ir.Arch) ir.Varnode {
	if int(r.Size) <= size {
		return r
	}
	off := r.Offset
	if arch != nil && arch.BigEndian {
		off += uint64(int(r.Size) - size)
	}
	return ir.Varnode{Space: r.Space, Offset: off, Size: uint8(size)}
}

// demand computes which bits of values their consumers need, so a value
// that only flows into bits something masks off, or into a call argument
// passed straight through, does not count as used.
type demand struct {
	users   map[*Value][]*Value
	results map[*Value]uint64
	memo    map[*Value]uint64
}

func (d *demand) need(v *Value) uint64 {
	if r, ok := d.memo[v]; ok {
		return r
	}
	d.memo[v] = 0 // cycles through phis demand nothing on their own
	m := ir.Mask(v.Size)
	r := d.results[v] & m
	for _, u := range d.users[v] {
		if r == m {
			break
		}
		switch {
		case u.Call != nil && u.Call.NArgs < 0 && passedThrough(u, v):
			// A register handed on unchanged: whether that is a use
			// depends on the callee (see Forwards).
		case u.Op == ir.OpPhi:
			r |= d.need(u) & m
		case u.Op == ir.OpIntAnd && u.Args[1].Op == OpConst && u.Args[0] == v:
			r |= d.need(u) & u.Args[1].Aux
		case u.Op == ir.OpIntOr || u.Op == ir.OpIntXor:
			r |= d.need(u) & m
		case u.Op == ir.OpIntZExt:
			r |= d.need(u) & m
		case u.Op == ir.OpSubpiece && u.Args[0] == v && u.Args[1].Op == OpConst && u.Args[1].Aux < 8:
			r |= d.need(u) << (8 * u.Args[1].Aux) & m
		case u.Op == ir.OpIntLeft && u.Args[0] == v && u.Args[1].Op == OpConst && u.Args[1].Aux < 64:
			r |= d.need(u) >> u.Args[1].Aux & m
		case u.Op == ir.OpIntRight && u.Args[0] == v && u.Args[1].Op == OpConst && u.Args[1].Aux < 64:
			r |= d.need(u) << u.Args[1].Aux & m
		default:
			r = m
		}
	}
	d.memo[v] = r
	return r
}

// passedThrough reports whether every use of v by call c is v, a
// register's entry value, as the candidate argument of that same register.
func passedThrough(c, v *Value) bool {
	if v.Op != OpInput {
		return false
	}
	start := argStart(c)
	for i, a := range c.Args {
		if a != v {
			continue
		}
		pos := i - start
		if pos < 0 || pos >= len(c.Call.Regs) || !overlapsVar(v.Var, c.Call.Regs[pos]) || c.Call.guessed[pos] {
			return false
		}
	}
	return true
}
