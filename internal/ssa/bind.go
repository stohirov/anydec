package ssa

import (
	"strings"

	"github.com/stohirov/decompile-anything/internal/ir"
)

// argStart is the index of a call's first argument.
func argStart(c *Value) int {
	if c.Op == ir.OpCallInd {
		return 1
	}
	return 0
}

// Calls returns f's call values.
func (f *Func) Calls() []*Value {
	var out []*Value
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Call != nil {
				out = append(out, v)
			}
		}
	}
	return out
}

// defined reports whether x is a value code produced, rather than a
// register's entry value passed through untouched or a clobbered one.
func (f *Func) defined(x *Value, reg ir.Varnode) bool {
	if (x.Op == ir.OpSubpiece || x.Op == ir.OpIntZExt) && x.Args[0].Op == OpInput {
		x = x.Args[0] // part of a wider register's entry value, or a parameter widened back to it
	}
	switch x.Op {
	case OpUndef:
		return false
	case OpInput:
		return !(x.Var.Space == reg.Space && x.Var.Offset <= int64(reg.Offset) && int64(reg.Offset) < x.Var.Offset+int64(x.Var.Size))
	}
	return true
}

// guessArgs builds a prototype for a call whose callee is unknown: the
// argument registers up to the last one code set before the call (earlier
// ones left alone pass the caller's own values on).
func (f *Func) guessArgs(c *Value, abi *ABI, soft bool) *Proto {
	p := &Proto{}
	ni, nf := f.guessCounts(c, abi, soft)
	start := argStart(c)
	for i := range ni {
		p.Params = append(p.Params, Param{Reg: abi.IntParams[i], Size: c.Args[start+i].Size})
	}
	for i := range nf {
		x := c.Args[start+len(abi.IntParams)+i]
		p.Params = append(p.Params, Param{Reg: abi.FloatParams[i], Size: x.Size, Float: true})
	}
	return p
}

// guessCounts returns how many integer and float argument registers an
// unknown callee gets: up to the last one set, unless one in between was
// clobbered by an earlier call.
func (f *Func) guessCounts(c *Value, abi *ABI, soft bool) (ints, floats int) {
	start := argStart(c)
	count := func(regs []ir.Varnode, base int) int {
		n := 0
		for i, r := range regs {
			x := c.Args[start+base+i]
			if x.Op == OpUndef {
				break
			}
			if f.defined(x, r) {
				n = i + 1
			}
		}
		return n
	}
	ints = count(abi.IntParams, 0)
	if !soft {
		floats = count(abi.FloatParams, len(abi.IntParams))
	}
	return ints, floats
}

// BindArgs replaces each call's candidate arguments with the parameters
// of its callee's prototype (proto returns nil for unknown callees, whose
// arguments are guessed). Stack arguments become loads from the outgoing
// argument area, which stack promotion turns into variables.
//
// soft reports callees that pass everything in integer registers whatever
// the convention, like ARM's run-time helpers (__aeabi_*).
func (f *Func) BindArgs(abi *ABI, proto func(c *Value) *Proto, soft func(c *Value) bool) {
	for _, c := range f.Calls() {
		if c.Call.NArgs >= 0 {
			continue
		}
		p := proto(c)
		if p == nil {
			p = f.guessArgs(c, abi, soft != nil && soft(c))
		}
		c.Call.Proto = p
		start := argStart(c)
		if start == 1 && f.Arch != nil && strings.HasPrefix(f.Arch.Language, "ARM:") {
			// BX and BLX clear the mode bit of the target; C calls the
			// pointer as it is.
			if t := c.Args[0]; t.Op == ir.OpIntAnd && isConst(t.Args[1], 0xfffffffe) {
				c.Args[0] = t.Args[0]
			}
		}
		cands := c.Args[start : len(c.Args)-1]
		sp := c.Args[len(c.Args)-1]
		args := append([]*Value{}, c.Args[:start]...)
		for _, prm := range p.Params {
			var x *Value
			switch {
			case prm.Stack:
				addr := f.insertBefore(c, ir.OpIntAdd, sp.Size, sp, f.Const(uint64(prm.Offset), sp.Size))
				x = f.insertBefore(c, ir.OpLoad, prm.Size, addr)
				x.Aux = uint64(ir.SpaceRAM)
			default:
				idx := regIndex(abi, prm)
				if idx < 0 {
					x = f.insertBefore(c, OpUndef, prm.Size)
					break
				}
				x = cands[idx]
				if prm.Size < x.Size {
					x = f.insertBefore(c, ir.OpSubpiece, prm.Size, x, f.Const(0, 4))
				}
			}
			args = append(args, x)
		}
		c.Args = args
		c.Call.NArgs = len(p.Params)
	}
}

// regIndex returns a register parameter's position among a call's
// candidate arguments.
func regIndex(abi *ABI, p Param) int {
	same := func(r ir.Varnode) bool { return r.Space == p.Reg.Space && r.Offset == p.Reg.Offset }
	for i, r := range abi.IntParams {
		if !p.Float && same(r) {
			return i
		}
	}
	for i, r := range abi.FloatParams {
		if p.Float && same(r) {
			return len(abi.IntParams) + i
		}
	}
	return -1
}

// BindParams makes f.Params the entry values of the parameters in ps.
// Narrower parameters than their register's variable become their own
// values, widened where the code reads the whole register; stack
// parameters are assembled from the promoted slots they cover.
func (f *Func) BindParams(ps []Param) {
	entry := f.Blocks[0]
	var pre []*Value
	emit := func(op Op, size int, args ...*Value) *Value {
		v := f.newValue(op, size, f.Entry, args...)
		v.Block = entry
		pre = append(pre, v)
		return v
	}
	repl := map[*Value]*Value{}
	regs := f.regAtoms()[ir.SpaceRegister]
	var slots []*Var
	for _, p := range ps {
		if p.Stack {
			slot := &Var{Space: ir.SpaceStack, Offset: p.Offset, Size: p.Size}
			slots = append(slots, slot)
			f.Params = append(f.Params, f.Input(slot))
			continue
		}
		reg := lowBytes(p.Reg, 8, f.Arch)
		var atom *Var
		for _, a := range regs {
			if a.Offset <= int64(reg.Offset) && int64(reg.Offset)+int64(reg.Size) <= a.Offset+int64(a.Size) {
				atom = a
			}
		}
		if atom == nil {
			atom = &Var{Space: ir.SpaceRegister, Offset: int64(reg.Offset), Size: int(reg.Size)}
			if f.Arch != nil && f.Arch.Register != nil {
				atom.Name = f.Arch.Register(reg.Offset, reg.Size)
			}
		}
		in := f.Input(atom)
		if p.Size >= atom.Size {
			f.Params = append(f.Params, in)
			continue
		}
		// The parameter is the low part of the register's variable.
		pv := &Var{Space: ir.SpaceRegister, Offset: atom.Offset, Size: p.Size, Name: atom.Name}
		if f.Arch != nil && f.Arch.BigEndian {
			pv.Offset = atom.Offset + int64(atom.Size-p.Size)
		}
		if f.Arch != nil && f.Arch.Register != nil {
			if n := f.Arch.Register(uint64(pv.Offset), uint8(pv.Size)); n != "" {
				pv.Name = n
			}
		}
		param := f.Input(pv)
		f.Params = append(f.Params, param)
		repl[in] = emit(ir.OpIntZExt, atom.Size, param)
	}
	// Promoted stack slots in the parameter area read the slot parameters.
	if len(slots) > 0 {
		bd := &builder{f: f, arch: f.Arch, vars: map[ir.SpaceID][]*Var{ir.SpaceStack: slots}}
		scratch := &Block{}
		for v, in := range f.inputs {
			if v.Space != ir.SpaceStack || in.Op != OpInput || isSlot(slots, v) {
				continue
			}
			x := bd.read(scratch, ir.Varnode{Space: ir.SpaceStack, Offset: uint64(v.Offset), Size: uint8(v.Size)}, f.Entry)
			for _, s := range scratch.Values {
				if s.Op == OpRead {
					s.reset(ir.OpCopy, f.Input(s.Var))
				}
				s.Block = entry
			}
			pre = append(pre, scratch.Values...)
			scratch.Values = nil
			repl[in] = x
		}
	}
	entry.Values = append(pre, entry.Values...)
	f.replaceAllExcept(repl, pre)
}

// SetReturns makes every return pass back exactly rets, and records them
// in the prototype.
func (f *Func) SetReturns(rets []Ret) {
	if f.Proto == nil {
		f.Proto = &Proto{Known: true}
	}
	f.Proto.Returns = rets
	for _, b := range f.Blocks {
		if b.Kind != BlockReturn {
			continue
		}
		var res []*Value
		for _, r := range rets {
			var x *Value
			for i, reg := range f.RetRegs {
				if reg == r.Reg {
					x = b.Results[i]
				}
			}
			if x == nil {
				x = f.NewValue(b, OpUndef, r.Size, b.End)
			}
			if r.Size < x.Size {
				x = f.NewValue(b, ir.OpSubpiece, r.Size, b.End, x, f.Const(0, 4))
			}
			res = append(res, x)
		}
		b.Results = res
	}
}

func isSlot(slots []*Var, v *Var) bool {
	for _, s := range slots {
		if s == v {
			return true
		}
	}
	return false
}

// replaceAllExcept is replaceAll leaving the values in keep alone.
func (f *Func) replaceAllExcept(repl map[*Value]*Value, keep []*Value) {
	skip := map[*Value]bool{}
	for _, v := range keep {
		skip[v] = true
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if skip[v] {
				continue
			}
			for i, a := range v.Args {
				v.Args[i] = resolve(repl, a)
			}
		}
		if b.Control != nil {
			b.Control = resolve(repl, b.Control)
		}
		for i, r := range b.Results {
			b.Results[i] = resolve(repl, r)
		}
	}
}

// InferReturns decides what f returns from the values its returns leave in
// the return registers: an integer when code set the first integer return
// register, a register pair when the second holds the high half of the
// same computation, and a float when only the float register was set or
// a floating-point operation produced it.
func (f *Func) InferReturns(abi *ABI) []Ret {
	var rets []*Block
	for _, b := range f.Blocks {
		if b.Kind == BlockReturn {
			rets = append(rets, b)
		}
	}
	if len(rets) == 0 {
		return nil
	}
	idx := func(r ir.Varnode) int {
		for i, x := range f.RetRegs {
			if x == r {
				return i
			}
		}
		return -1
	}
	// set reports whether every return leaves a value code defined in r,
	// and whether it does along every path into the phis it returns.
	set := func(r ir.Varnode) (any, all bool) {
		i := idx(r)
		if i < 0 {
			return false, false
		}
		seen := map[*Value]bool{}
		var every func(x *Value) bool
		every = func(x *Value) bool {
			if x.Op != ir.OpPhi {
				return f.defined(x, r)
			}
			if seen[x] {
				return true
			}
			seen[x] = true
			for _, a := range x.Args {
				if !every(a) {
					return false
				}
			}
			return true
		}
		any, all = true, true
		for _, b := range rets {
			any = any && f.defined(b.Results[i], r)
			all = all && every(b.Results[i])
		}
		return any, any && all
	}
	width := func(r ir.Varnode, float bool) int {
		i := idx(r)
		w := 0
		for _, b := range rets {
			w = max(w, lowWidth(b.Results[i], f))
		}
		if float {
			return min(w, 8) // a double may fill the pair s0 starts
		}
		return min(w, int(r.Size))
	}
	floatMade := func(r ir.Varnode) bool {
		i := idx(r)
		for _, b := range rets {
			if !floatResult(lowPart(b.Results[i], f)) {
				return false
			}
		}
		return true
	}
	var intRet, floatRet, intAll, floatAll bool
	if len(abi.IntReturns) > 0 {
		intRet, intAll = set(abi.IntReturns[0])
	}
	if len(abi.FloatReturns) > 0 {
		floatRet, floatAll = set(abi.FloatReturns[0])
	}
	if intRet && floatRet && intAll != floatAll {
		// Only one is set on every path.
		intRet, floatRet = intAll, floatAll
	}
	if intRet && floatRet {
		// Both registers hold something: the one whose value was moved
		// from the other's is the result (vmov d0, r0, r1 after a soft-
		// float helper; vmov r0, s0 after a conversion).
		i, j := idx(abi.IntReturns[0]), idx(abi.FloatReturns[0])
		fromInt, fromFloat := true, true
		for _, b := range rets {
			fromInt = fromInt && reaches(b.Results[j], b.Results[i], 6)
			fromFloat = fromFloat && reaches(b.Results[i], b.Results[j], 6)
		}
		switch {
		case fromInt && !fromFloat:
			intRet = false
		case fromFloat && !fromInt:
			floatRet = false
		case floatMade(abi.FloatReturns[0]):
			intRet = false
		default:
			floatRet = false
		}
	}
	switch {
	case intRet:
		r0 := abi.IntReturns[0]
		out := []Ret{{Reg: r0, Size: width(r0, false)}}
		if len(abi.IntReturns) > 1 && r0.Size < 8 && out[0].Size == int(r0.Size) {
			r1 := abi.IntReturns[1]
			i0, i1 := idx(r0), idx(r1)
			pair := i1 >= 0
			for _, b := range rets {
				pair = pair && f.defined(b.Results[i1], r1) && halves(b.Results[i0], b.Results[i1])
			}
			if pair {
				out = append(out, Ret{Reg: r1, Size: int(r1.Size)})
			}
		}
		return out
	case floatRet:
		r := abi.FloatReturns[0]
		return []Ret{{Reg: r, Size: width(r, true), Float: true}}
	}
	return nil
}

// reaches reports whether v is computed from x, looking depth ops back.
func reaches(v, x *Value, depth int) bool {
	if v == x {
		return true
	}
	if depth == 0 || v.Op == ir.OpPhi {
		return false
	}
	for _, a := range v.Args {
		if reaches(a, x, depth-1) {
			return true
		}
	}
	return false
}

// lowPart strips the merge a partial register write leaves around a value
// (old & ~mask | zext(x)) and returns x.
func lowPart(v *Value, f *Func) *Value {
	if v.Op == ir.OpIntOr {
		for i := range 2 {
			z := v.Args[1-i]
			if v.Args[i].Op == ir.OpIntAnd && z.Op == ir.OpIntZExt {
				return z.Args[0]
			}
		}
	}
	// Writing a 32-bit register clears the upper half on x86-64 and
	// AArch64; a narrower value zero-extended on purpose (MOVZX) stays
	// extended.
	if v.Op == ir.OpIntZExt && v.Args[0].Size >= 4 {
		return v.Args[0]
	}
	return v
}

// lowWidth is how many low bytes of v carry the result.
func lowWidth(v *Value, f *Func) int {
	if v.Op == ir.OpIntAnd {
		if k, ok := v.Args[1].IsConst(); ok {
			for _, n := range []int{1, 2, 4} {
				if k == ir.Mask(n) {
					return n
				}
			}
		}
	}
	return lowPart(v, f).Size
}

func floatResult(v *Value) bool {
	switch v.Op {
	case ir.OpFloatAdd, ir.OpFloatSub, ir.OpFloatMult, ir.OpFloatDiv, ir.OpFloatNeg, ir.OpFloatAbs,
		ir.OpFloatSqrt, ir.OpFloatInt2Float, ir.OpFloatFloat2Float, ir.OpFloatCeil, ir.OpFloatFloor, ir.OpFloatRound:
		return true
	case ir.OpPhi:
		for _, a := range v.Args {
			if a != v && floatResult(a) {
				return true
			}
		}
	}
	return false
}

// halves reports whether lo and hi are the two halves of one wider
// computation: pieces of the same value, results of the same call, or an
// addition or subtraction whose high half takes the carry of the low.
func halves(lo, hi *Value) bool {
	if lo.Op == ir.OpSubpiece && hi.Op == ir.OpSubpiece && lo.Args[0] == hi.Args[0] &&
		isZero(lo.Args[1]) && isConst(hi.Args[1], uint64(lo.Size)) {
		return true
	}
	if lo.Op == OpCallOut && hi.Op == OpCallOut && lo.Args[0] == hi.Args[0] {
		return true
	}
	if lo.Op == ir.OpPhi && hi.Op == ir.OpPhi && lo.Block == hi.Block {
		for i := range lo.Args {
			if lo.Args[i] != lo && !halves(lo.Args[i], hi.Args[i]) {
				return false
			}
		}
		return true
	}
	// A carry or borrow of lo's operands inside hi, or the high half of
	// the wide value lo is the low half of (a long multiply).
	if len(lo.Args) != 2 {
		return false
	}
	found := false
	var walk func(v *Value, depth int)
	walk = func(v *Value, depth int) {
		if found || depth > 4 {
			return
		}
		if lo.Op == ir.OpSubpiece && isZero(lo.Args[1]) && v.Op == ir.OpSubpiece && v.Args[0] == lo.Args[0] &&
			isConst(v.Args[1], uint64(lo.Size)) {
			found = true
			return
		}
		switch v.Op {
		case ir.OpIntCarry, ir.OpIntLess, ir.OpIntSBorrow, ir.OpIntSCarry:
			if (v.Args[0] == lo.Args[0] && v.Args[1] == lo.Args[1]) || (v.Args[0] == lo.Args[1] && v.Args[1] == lo.Args[0]) {
				found = true
			}
		}
		for _, a := range v.Args {
			walk(a, depth+1)
		}
	}
	walk(hi, 0)
	return found
}

// BindResults gives each call its callee's result: the call value takes
// the returned size, register values after the call become its pieces,
// and the other registers the call wrote become undefined. For unknown
// callees the result is guessed from which return registers the caller
// reads.
func (f *Func) BindResults(abi *ABI, proto func(c *Value) *Proto) {
	outs := map[*Value][]*Value{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == OpCallOut {
				outs[v.Args[0]] = append(outs[v.Args[0]], v)
			}
		}
	}
	// Results do not count: before SetReturns they read every return
	// register, wanted or not.
	used := f.usedValues(false)
	for _, b := range f.Blocks {
		for i, r := range b.Results {
			if i < len(f.RetRegs) && (len(abi.IntReturns) > 0 && f.RetRegs[i] == abi.IntReturns[0] ||
				len(abi.FloatReturns) > 0 && f.RetRegs[i] == abi.FloatReturns[0]) {
				used[r] = true
			}
		}
	}
	for _, c := range f.Calls() {
		p := proto(c)
		var rets []Ret
		if p != nil {
			rets = p.Returns
		} else {
			rets = guessReturns(abi, outs[c], used)
			if c.Call.Proto != nil {
				c.Call.Proto.Returns = rets
			}
		}
		c.Size = 0
		for _, r := range rets {
			c.Size += r.Size
		}
		for _, o := range outs[c] {
			var x *Value
			off := 0
			for _, r := range rets {
				if overlapsVar(o.Var, r.Reg) {
					x = c
					if len(rets) > 1 {
						x = f.insertBefore(o, ir.OpSubpiece, r.Size, c, f.Const(uint64(off), 4))
					}
					break
				}
				off += r.Size
			}
			switch {
			case x == nil:
				o.reset(OpUndef)
			case x.Size == o.Size:
				o.copyOf(x)
			case x.Size < o.Size:
				o.reset(ir.OpIntZExt, x)
			default:
				o.reset(ir.OpSubpiece, x, f.Const(0, 4))
			}
		}
	}
}

func overlapsVar(v *Var, r ir.Varnode) bool {
	return v.Space == r.Space && int64(r.Offset) < v.Offset+int64(v.Size) && v.Offset < int64(r.Offset)+int64(r.Size)
}

// usedValues returns the values something reads: other values, controls
// and, with results set, returns.
func (f *Func) usedValues(results bool) map[*Value]bool {
	u := map[*Value]bool{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for _, a := range v.Args {
				u[a] = true
			}
		}
		if b.Control != nil {
			u[b.Control] = true
		}
		if results {
			for _, r := range b.Results {
				u[r] = true
			}
		}
	}
	return u
}

// guessReturns picks the result of an unknown callee from the registers
// the caller reads after the call.
func guessReturns(abi *ABI, outs []*Value, used map[*Value]bool) []Ret {
	find := func(r ir.Varnode) *Value {
		for _, o := range outs {
			if used[o] && overlapsVar(o.Var, r) {
				return o
			}
		}
		return nil
	}
	if len(abi.IntReturns) > 0 {
		r0 := abi.IntReturns[0]
		if o := find(r0); o != nil {
			out := []Ret{{Reg: r0, Size: min(o.Size, int(r0.Size))}}
			if len(abi.IntReturns) > 1 && r0.Size < 8 {
				if find(abi.IntReturns[1]) != nil {
					out = append(out, Ret{Reg: abi.IntReturns[1], Size: int(abi.IntReturns[1].Size)})
				}
			}
			return out
		}
	}
	if len(abi.FloatReturns) > 0 {
		r := abi.FloatReturns[0]
		if o := find(r); o != nil {
			return []Ret{{Reg: r, Size: min(o.Size, 8), Float: true}}
		}
	}
	return nil
}
