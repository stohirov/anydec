package emit

import (
	"fmt"
	"strings"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/ssa"
	"github.com/stohirov/decompile-anything/internal/structure"
)

// Leaving SSA: every phi becomes a variable, assigned by copies at the end
// of its predecessors (critical edges are split first, so each copy has a
// block to itself, and a group of copies on one edge is ordered as a
// parallel assignment). Values used once in their own block are inlined
// into the use when no store or call lies between; the others get a
// variable of their own.

type use struct {
	b   *ssa.Block
	pos int // index in b.Values; len(b.Values) for the block's end
}

type funcEmitter struct {
	u      *Unit
	f      *ssa.Func
	res    *structure.Result
	nuses  map[*ssa.Value]int
	site   map[*ssa.Value]use
	inline map[*ssa.Value]bool
	names  map[*ssa.Value]string
	float  map[*ssa.Value]bool
	taken  map[string]bool
	decls  []string
	// override renames values while a parallel copy is ordered.
	override map[*ssa.Value]string
	sb       strings.Builder
	depth    int
	nextTemp int
	frameSP  *ssa.Value // the stack pointer's entry value, when the frame stays memory
	frame    string     // declaration of the frame array
}

func newFuncEmitter(u *Unit, f *ssa.Func) *funcEmitter {
	return &funcEmitter{
		u: u, f: f, nuses: map[*ssa.Value]int{}, site: map[*ssa.Value]use{}, inline: map[*ssa.Value]bool{},
		names: map[*ssa.Value]string{}, float: map[*ssa.Value]bool{}, taken: map[string]bool{},
		override: map[*ssa.Value]string{},
	}
}

func (e *funcEmitter) emit() string {
	f := e.f
	f.SplitCriticalEdges()
	e.res = structure.Structure(f)
	e.countUses()
	e.inferFloats()
	e.classify()
	e.nameValues()

	var body strings.Builder
	saved := e.sb
	e.sb = strings.Builder{}
	e.depth = 1
	e.stackParams()
	e.seq(e.res.Body)
	body.WriteString(e.sb.String())
	e.sb = saved

	var out strings.Builder
	for _, w := range f.Warnings {
		fmt.Fprintf(&out, "/* warning: %s */\n", w)
	}
	fmt.Fprintf(&out, "%s\n{\n", e.u.signature(f))
	if e.frame != "" {
		fmt.Fprintf(&out, "    %s\n", e.frame)
	}
	for _, d := range e.decls {
		fmt.Fprintf(&out, "    %s;\n", d)
	}
	if e.frame != "" || len(e.decls) > 0 {
		out.WriteString("\n")
	}
	out.WriteString(body.String())
	out.WriteString("}\n")
	return out.String()
}

// countUses records how often each value is used and, for values used
// once, where.
func (e *funcEmitter) countUses() {
	add := func(v *ssa.Value, at use) {
		if v == nil {
			return
		}
		e.nuses[v]++
		e.site[v] = at
	}
	for _, b := range e.f.Blocks {
		for i, v := range b.Values {
			if v.Op == ir.OpPhi {
				for j, a := range v.Args {
					p := b.Preds[j]
					add(a, use{p, len(p.Values)})
				}
				continue
			}
			for _, a := range v.Args {
				add(a, use{b, i})
			}
		}
		add(b.Control, use{b, len(b.Values)})
		for _, r := range b.Results {
			add(r, use{b, len(b.Values)})
		}
	}
}

// inferFloats decides which values hold floating-point numbers: results of
// float operations, float parameters and call results, and loads, phis
// and inputs that float operations consume.
func (e *funcEmitter) inferFloats() {
	f := e.f
	for i, p := range f.Params {
		if f.Proto != nil && i < len(f.Proto.Params) && f.Proto.Params[i].Float {
			e.float[p] = true
		}
	}
	consumers := map[*ssa.Value][]*ssa.Value{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if makesFloat(v.Op) {
				e.float[v] = true
			}
			if v.Call != nil && v.Call.Proto != nil && len(v.Call.Proto.Returns) == 1 && v.Call.Proto.Returns[0].Float {
				e.float[v] = true
			}
			for i, a := range v.Args {
				consumers[a] = append(consumers[a], v)
				if wantsFloat(v, i) && (a.Size == 4 || a.Size == 8) && neutral(a) && !e.isParam(a) {
					e.float[a] = true
				}
			}
		}
	}
	// Phis join floats.
	for changed := true; changed; {
		changed = false
		for _, b := range f.Blocks {
			for _, v := range b.Values {
				if v.Op != ir.OpPhi || e.float[v] || (v.Size != 4 && v.Size != 8) {
					continue
				}
				for _, a := range v.Args {
					if e.float[a] {
						e.float[v] = true
						changed = true
						break
					}
				}
				if !e.float[v] {
					continue
				}
				for _, a := range v.Args {
					if neutral(a) && !e.isParam(a) && !e.float[a] && a.Size == v.Size {
						e.float[a] = true
					}
				}
			}
		}
	}
}

func makesFloat(op ssa.Op) bool {
	switch op {
	case ir.OpFloatAdd, ir.OpFloatSub, ir.OpFloatMult, ir.OpFloatDiv, ir.OpFloatNeg, ir.OpFloatAbs, ir.OpFloatSqrt,
		ir.OpFloatInt2Float, ir.OpFloatFloat2Float, ir.OpFloatCeil, ir.OpFloatFloor, ir.OpFloatRound:
		return true
	}
	return false
}

// neutral values have no type of their own: they hold whatever is put in.
func neutral(v *ssa.Value) bool {
	switch v.Op {
	case ir.OpLoad, ir.OpPhi, ssa.OpInput:
		return true
	}
	return false
}

// isParam reports whether v is a parameter, whose type the prototype fixes.
func (e *funcEmitter) isParam(v *ssa.Value) bool {
	for _, p := range e.f.Params {
		if p == v {
			return true
		}
	}
	return false
}

// wantsFloat reports whether v reads argument i as a floating-point value.
func wantsFloat(v *ssa.Value, i int) bool {
	switch v.Op {
	case ir.OpFloatAdd, ir.OpFloatSub, ir.OpFloatMult, ir.OpFloatDiv, ir.OpFloatNeg, ir.OpFloatAbs, ir.OpFloatSqrt,
		ir.OpFloatFloat2Float, ir.OpFloatCeil, ir.OpFloatFloor, ir.OpFloatRound, ir.OpFloatTrunc,
		ir.OpFloatEqual, ir.OpFloatNotEqual, ir.OpFloatLess, ir.OpFloatLessEqual, ir.OpFloatNaN:
		return true
	}
	return false
}

// classify decides which values are inlined into their single use.
func (e *funcEmitter) classify() {
	for _, b := range e.f.Blocks {
		for i, v := range b.Values {
			switch {
			case v.Op == ir.OpPhi || v.HasEffect() || v.Op == ssa.OpCallOut:
			case v.Op == ir.OpCopy || v.Op == ssa.OpUndef:
				e.inline[v] = true
			case e.nuses[v] == 1:
				s := e.site[v]
				if s.b != b && len(s.b.Values) == 0 && len(s.b.Preds) == 1 && s.b.Preds[0] == b {
					// A copy on the edge leaving b: the end of b, as far
					// as memory goes.
					s = use{b, len(b.Values)}
				}
				if s.b != b {
					break
				}
				if e.readsMemory(v) {
					safe := true
					for _, w := range b.Values[i+1 : s.pos] {
						if w.HasEffect() {
							safe = false
							break
						}
					}
					if !safe {
						break
					}
				}
				e.inline[v] = true
			}
		}
	}
}

// readsMemory reports whether v's expression, with inlined operands,
// loads from memory.
func (e *funcEmitter) readsMemory(v *ssa.Value) bool {
	if v.Op == ir.OpLoad {
		return true
	}
	for _, a := range v.Args {
		if e.inline[a] && e.readsMemory(a) {
			return true
		}
	}
	return false
}

func (e *funcEmitter) unique(base string) string {
	name := ident(base)
	if !e.taken[name] {
		e.taken[name] = true
		return name
	}
	for i := 2; ; i++ {
		n := fmt.Sprintf("%s_%d", name, i)
		if !e.taken[n] {
			e.taken[n] = true
			return n
		}
	}
}

func (e *funcEmitter) nameValues() {
	f := e.f
	for _, fn := range e.u.Funcs {
		e.taken[ident(fn.Name)] = true
	}
	for i, p := range f.Params {
		e.names[p] = e.unique(fmt.Sprintf("a%d", i+1))
	}
	if f.SP != nil {
		e.frameSP = e.inputUsed(f.SP)
	}
	if e.frameSP != nil {
		e.names[e.frameSP] = e.unique("sp0")
		e.setupFrame()
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for _, a := range v.Args {
				e.nameInput(a)
			}
			if v.Op == ir.OpPhi {
				e.names[v] = e.unique(varName(v.Var))
				e.decls = append(e.decls, fmt.Sprintf("%s %s", e.ctype(v), e.names[v]))
				continue
			}
			if e.inline[v] || v.Size == 0 || (v.Call != nil && e.nuses[v] == 0) || (v.HasEffect() && v.Call == nil && v.Op != ir.OpCallOther) {
				continue
			}
			if v.Op == ir.OpCallOther && e.nuses[v] == 0 {
				continue
			}
			e.nextTemp++
			e.names[v] = e.unique(fmt.Sprintf("v%d", e.nextTemp))
			e.decls = append(e.decls, fmt.Sprintf("%s %s", e.ctype(v), e.names[v]))
		}
		e.nameInput(b.Control)
		for _, r := range b.Results {
			e.nameInput(r)
		}
	}
}

// inputUsed returns the entry value of vr if anything uses it.
func (e *funcEmitter) inputUsed(vr *ssa.Var) *ssa.Value {
	for v := range e.nuses {
		if v.Op == ssa.OpInput && v.Var == vr {
			return v
		}
	}
	return nil
}

// nameInput declares entry values that are not parameters: registers or
// stack slots read before anything wrote them.
func (e *funcEmitter) nameInput(v *ssa.Value) {
	if v == nil || v.Op != ssa.OpInput || e.names[v] != "" {
		return
	}
	e.names[v] = e.unique("uninit_" + varName(v.Var))
	e.decls = append(e.decls, fmt.Sprintf("%s %s", e.ctype(v), e.names[v]))
}

func varName(v *ssa.Var) string {
	if v == nil {
		return "x"
	}
	switch v.Space {
	case ir.SpaceStack:
		if v.Offset < 0 {
			return fmt.Sprintf("local_%x", -v.Offset)
		}
		return fmt.Sprintf("arg_%x", v.Offset)
	case ir.SpaceRegister:
		if v.Name != "" {
			return strings.ToLower(v.Name)
		}
	}
	return "t"
}

// setupFrame declares the memory of a frame whose addresses escape: an
// array spanning every stack offset the function touches, with sp0 its
// entry stack pointer.
func (e *funcEmitter) setupFrame() {
	lo, hi := int64(0), int64(0)
	for _, b := range e.f.Blocks {
		for _, v := range b.Values {
			if off, ok := e.f.SPOffset(v); ok {
				lo = min(lo, off)
			}
		}
	}
	for _, a := range e.f.Frame().Accesses {
		lo = min(lo, a.Offset)
		hi = max(hi, a.Offset+int64(a.Size))
	}
	if e.f.Proto != nil {
		for _, p := range e.f.Proto.Params {
			if p.Stack {
				hi = max(hi, p.Offset+int64(p.Size))
			}
		}
	}
	lo &^= 15
	size := hi - lo + 16
	t := intType(e.u.ptrSize())
	e.frame = fmt.Sprintf("uint8_t frame[%d] __attribute__((aligned(16)));\n    %s %s = (%s)frame + %#x;", size, t, e.names[e.frameSP], t, -lo)
}

// stackParams copies stack parameters into a memory frame, where the
// code reads them.
func (e *funcEmitter) stackParams() {
	if e.frameSP == nil || e.f.Proto == nil {
		return
	}
	for i, p := range e.f.Proto.Params {
		if p.Stack {
			e.line(fmt.Sprintf("*(%s *)(%s + %#x) = %s;", paramType(p), e.names[e.frameSP], p.Offset, e.names[e.f.Params[i]]))
		}
	}
}

func (e *funcEmitter) ctype(v *ssa.Value) string {
	if e.float[v] && (v.Size == 4 || v.Size == 8) {
		return floatType(v.Size)
	}
	return intType(v.Size)
}

func (e *funcEmitter) line(s string) {
	e.sb.WriteString(strings.Repeat("    ", e.depth))
	e.sb.WriteString(s)
	e.sb.WriteString("\n")
}

func (e *funcEmitter) lineAt(s string, addr uint64) {
	if e.u.Addresses && addr != 0 {
		s = fmt.Sprintf("%s  /* %#x */", s, addr)
	}
	e.line(s)
}

func (e *funcEmitter) label(b *ssa.Block) string { return fmt.Sprintf("L_%x_%d", b.Start, b.ID) }

func (e *funcEmitter) seq(s structure.Seq) {
	for _, n := range s {
		e.node(n)
	}
}

func (e *funcEmitter) node(n structure.Node) {
	switch n := n.(type) {
	case structure.Seq:
		e.seq(n)
	case structure.Block:
		if e.res.Labels[n.B] {
			e.depth--
			e.line(e.label(n.B) + ":;")
			e.depth++
		}
		e.block(n.B)
	case structure.If:
		cond := e.cond(n.B.Control, false)
		then, els := n.Then, n.Else
		if len(then) == 0 && len(els) > 0 {
			then, els = els, then
			cond = e.cond(n.B.Control, true)
		}
		e.lineAt(fmt.Sprintf("if (%s) {", cond.s), n.B.End)
		e.nested(then)
		if len(els) > 0 {
			if len(els) == 1 {
				if inner, ok := els[0].(structure.If); ok && !e.res.Labels[inner.B] && len(e.statements(inner.B)) == 0 {
					e.line("} else")
					e.node(els[0])
					return
				}
			}
			e.line("} else {")
			e.nested(els)
		}
		e.line("}")
	case structure.Loop:
		e.loop(n)
	case structure.Switch:
		e.switchNode(n)
	case structure.Break:
		e.line("break;")
	case structure.Continue:
		e.line("continue;")
	case structure.Goto:
		e.line(fmt.Sprintf("goto %s;", e.label(n.Target)))
	case structure.Return:
		e.ret(n.B)
	case structure.Stop:
		e.lineAt("__builtin_trap();", n.B.End)
	}
}

func (e *funcEmitter) nested(s structure.Seq) {
	e.depth++
	e.seq(s)
	e.depth--
}

// loop prints while (1) loops, turning a leading conditional break into
// the loop condition.
func (e *funcEmitter) loop(n structure.Loop) {
	body := trimContinue(n.Body)
	if len(body) >= 2 {
		if blk, ok := body[0].(structure.Block); ok && !e.res.Labels[blk.B] && len(e.statements(blk.B)) == 0 {
			if iff, ok := body[1].(structure.If); ok && iff.B == blk.B {
				cond, ncond := e.cond(iff.B.Control, false), e.cond(iff.B.Control, true)
				switch {
				case isBreak(iff.Then) && len(iff.Else) == 0:
					e.lineAt(fmt.Sprintf("while (%s) {", ncond.s), iff.B.End)
					e.nested(append(structure.Seq{}, body[2:]...))
					e.line("}")
					return
				case isBreak(iff.Else) && len(iff.Then) == 0:
					e.lineAt(fmt.Sprintf("while (%s) {", cond.s), iff.B.End)
					e.nested(append(structure.Seq{}, body[2:]...))
					e.line("}")
					return
				case isBreak(iff.Then):
					e.lineAt(fmt.Sprintf("while (%s) {", ncond.s), iff.B.End)
					e.nested(trimContinue(append(append(structure.Seq{}, iff.Else...), body[2:]...)))
					e.line("}")
					return
				case isBreak(iff.Else):
					e.lineAt(fmt.Sprintf("while (%s) {", cond.s), iff.B.End)
					e.nested(trimContinue(append(append(structure.Seq{}, iff.Then...), body[2:]...)))
					e.line("}")
					return
				}
			}
		}
	}
	e.line("while (1) {")
	e.nested(body)
	e.line("}")
}

// trimContinue drops a continue that ends a loop body, where control
// returns to the loop's head anyway.
func trimContinue(s structure.Seq) structure.Seq {
	if len(s) == 0 {
		return s
	}
	switch n := s[len(s)-1].(type) {
	case structure.Continue:
		return s[:len(s)-1]
	case structure.If:
		out := append(structure.Seq{}, s...)
		out[len(out)-1] = structure.If{B: n.B, Then: trimContinue(n.Then), Else: trimContinue(n.Else)}
		return out
	}
	return s
}

func isBreak(s structure.Seq) bool {
	if len(s) != 1 {
		return false
	}
	_, ok := s[0].(structure.Break)
	return ok
}

// block prints the statements of b, then the copies into its successor's
// phis.
func (e *funcEmitter) block(b *ssa.Block) {
	for _, s := range e.statements(b) {
		e.lineAt(s.text, s.addr)
	}
}

type stmt struct {
	text string
	addr uint64
}

func (e *funcEmitter) statements(b *ssa.Block) []stmt {
	var out []stmt
	for _, v := range b.Values {
		if s := e.statement(v); s != "" {
			out = append(out, stmt{s, v.Origin})
		}
	}
	if len(b.Succs) == 1 {
		out = append(out, e.copies(b, b.Succs[0])...)
	}
	return out
}

// statement renders v when it is a statement: a store, a call, or a value
// with a variable of its own.
func (e *funcEmitter) statement(v *ssa.Value) string {
	switch {
	case v.Op == ir.OpPhi || e.inline[v]:
		return ""
	case v.Op == ir.OpStore:
		val := v.Args[1]
		t := e.ctype(val)
		return fmt.Sprintf("*(%s *)%s = %s;", t, e.pointer(v.Args[0]), e.expr(val).s)
	case v.Call != nil || v.Op == ir.OpCallOther:
		call := e.call(v)
		if name := e.names[v]; name != "" {
			return fmt.Sprintf("%s = %s;", name, call)
		}
		return call + ";"
	case e.names[v] != "":
		return fmt.Sprintf("%s = %s;", e.names[v], e.rhs(v).s)
	}
	return ""
}

// copies assigns the phis of s their values on the edge from b, ordered
// so no copy overwrites a variable a later copy still reads.
func (e *funcEmitter) copies(b, s *ssa.Block) []stmt {
	i := -1
	for j, p := range s.Preds {
		if p == b {
			i = j
		}
	}
	if i < 0 {
		return nil
	}
	type cp struct {
		dst  *ssa.Value
		src  *ssa.Value
		done bool
	}
	var cps []*cp
	for _, v := range s.Values {
		if v.Op == ir.OpPhi && v.Args[i] != v {
			cps = append(cps, &cp{dst: v, src: v.Args[i]})
		}
	}
	var out []stmt
	saved := map[*ssa.Value]bool{} // destinations whose old value a temporary holds
	reads := func(c *cp, x *ssa.Value) bool { return !saved[x] && e.mentions(c.src, x) }
	for left := len(cps); left > 0; {
		progress := false
		for _, c := range cps {
			if c.done {
				continue
			}
			blocked := false
			for _, o := range cps {
				if o != c && !o.done && reads(o, c.dst) {
					blocked = true
					break
				}
			}
			if blocked {
				continue
			}
			out = append(out, stmt{fmt.Sprintf("%s = %s;", e.names[c.dst], e.operand(c.src, e.float[c.dst]).s), b.End})
			c.done = true
			left--
			progress = true
		}
		if progress || left == 0 {
			continue
		}
		// A cycle: save one destination and read the saved copy instead.
		for _, c := range cps {
			if c.done {
				continue
			}
			tmp := e.unique(e.names[c.dst] + "_old")
			e.decls = append(e.decls, fmt.Sprintf("%s %s", e.ctype(c.dst), tmp))
			out = append(out, stmt{fmt.Sprintf("%s = %s;", tmp, e.names[c.dst]), b.End})
			e.override[c.dst] = tmp
			saved[c.dst] = true
			break
		}
	}
	clear(e.override)
	return out
}

// mentions reports whether the expression for v reads the variable of x.
func (e *funcEmitter) mentions(v, x *ssa.Value) bool {
	if v == x {
		return true
	}
	if !e.inline[v] {
		return false
	}
	for _, a := range v.Args {
		if e.mentions(a, x) {
			return true
		}
	}
	return false
}

func (e *funcEmitter) ret(b *ssa.Block) {
	p := e.f.Proto
	switch {
	case p == nil || len(p.Returns) == 0 || len(b.Results) == 0:
		e.lineAt("return;", b.End)
	case len(p.Returns) == 1:
		r := p.Returns[0]
		x := e.operand(b.Results[0], r.Float && (r.Size == 4 || r.Size == 8))
		e.lineAt(fmt.Sprintf("return %s;", x.s), b.End)
	default:
		lo, hi := b.Results[0], b.Results[1]
		t := retType(p)
		e.lineAt(fmt.Sprintf("return (%s)%s << %d | %s;", t, wrap(e.expr(hi), precUnary), 8*p.Returns[0].Size, wrap(e.expr(lo), precShift)), b.End)
	}
}

// switchNode prints a jump table dispatch on the value the table indexes.
func (e *funcEmitter) switchNode(n structure.Switch) {
	b := n.B
	x, values := e.switchVar(b)
	head := "switch (" + e.expr(x).s + ") {"
	if x == nil {
		head = "switch (" + e.expr(b.Control).s + ") { /* jump target */"
	}
	e.lineAt(head, b.End)
	for _, c := range n.Cases {
		var labels []string
		if x == nil {
			for _, jc := range b.Cases {
				if jc.Target == c.Target.Start {
					labels = append(labels, fmt.Sprintf("case %#x:", jc.Target))
					break
				}
			}
		}
		for _, xv := range values[c.Target.Start] {
			labels = append(labels, fmt.Sprintf("case %s:", e.literal(xv, x.Size)))
		}
		if len(labels) == 0 {
			labels = []string{"default:"}
		}
		for _, l := range labels {
			e.line(l)
		}
		e.nested(c.Body)
	}
	e.line("}")
}

// switchVar finds the value a jump table is indexed by: a value in the
// target's computation that, set to suitable values, yields every target.
// Deeper values are tried first, so the variable wins over addresses
// computed from it. It returns the value and the case values selecting
// each target address.
func (e *funcEmitter) switchVar(b *ssa.Block) (*ssa.Value, map[uint64][]uint64) {
	var cands []*ssa.Value
	seen := map[*ssa.Value]bool{}
	address := map[*ssa.Value]bool{} // loaded from directly: a pointer, not an index
	work := []*ssa.Value{b.Control}
	for len(work) > 0 && len(cands) < 32 {
		v := work[0]
		work = work[1:]
		if seen[v] || v.Op == ssa.OpConst {
			continue
		}
		seen[v] = true
		if v.Op == ir.OpLoad {
			address[v.Args[0]] = true
		}
		if v != b.Control && v.Size <= 8 {
			cands = append(cands, v)
		}
		work = append(work, v.Args...)
	}
	targets := map[uint64]bool{}
	for _, jc := range b.Cases {
		targets[jc.Target] = true
	}
	for i := len(cands) - 1; i >= 0; i-- {
		x := cands[i]
		if address[x] || !(e.names[x] != "" || e.inline[x] || x.Op == ssa.OpInput) {
			continue
		}
		var tries []uint64
		if x.Size == 1 {
			for k := range uint64(256) {
				tries = append(tries, k)
			}
		} else {
			for k := int64(-1024); k <= 1024; k++ {
				tries = append(tries, uint64(k)&ir.Mask(x.Size))
			}
			for _, jc := range b.Cases {
				tries = append(tries, uint64(jc.Value)&ir.Mask(x.Size))
			}
		}
		hits := map[uint64][]uint64{}
		done := map[uint64]bool{}
		for _, xv := range tries {
			if done[xv] {
				continue
			}
			done[xv] = true
			if t, ok := e.eval(b.Control, x, xv, 0); ok && targets[t] {
				hits[t] = append(hits[t], xv)
			}
		}
		if len(hits) == len(targets) {
			return x, hits
		}
	}
	return nil, nil
}

// eval computes v with x set to xv, reading read-only memory.
func (e *funcEmitter) eval(v, x *ssa.Value, xv uint64, depth int) (uint64, bool) {
	if v == x {
		return xv, true
	}
	if depth > 24 {
		return 0, false
	}
	if c, ok := v.IsConst(); ok {
		return c, true
	}
	if v.Op == ir.OpLoad {
		a, ok := e.eval(v.Args[0], x, xv, depth+1)
		if !ok || e.u.Img == nil {
			return 0, false
		}
		return e.u.Img.ReadOnly(a, v.Size)
	}
	if v.Op >= ssa.OpConst || v.Op == ir.OpPhi || v.HasEffect() || v.Size > 8 {
		return 0, false
	}
	in := make([]uint64, len(v.Args))
	sizes := make([]int, len(v.Args))
	for i, a := range v.Args {
		r, ok := e.eval(a, x, xv, depth+1)
		if !ok {
			return 0, false
		}
		in[i], sizes[i] = r, a.Size
	}
	r, err := ir.Eval(v.Op, v.Size, in, sizes)
	return r, err == nil
}

// call renders a call value.
func (e *funcEmitter) call(v *ssa.Value) string {
	if v.Op == ir.OpCallOther {
		name := fmt.Sprintf("userop%d", v.Aux)
		if e.f.Arch != nil && int(v.Aux) < len(e.f.Arch.UserOps) {
			name = e.f.Arch.UserOps[v.Aux]
		}
		name = "__anydec_" + ident(name)
		im := e.u.importUse(name)
		im.callers++
		if v.Size > 0 {
			im.ret = intType(v.Size)
		}
		var args []string
		for _, a := range v.Args {
			args = append(args, e.expr(a).s)
		}
		return fmt.Sprintf("%s(%s)", name, strings.Join(args, ", "))
	}
	p := v.Call.Proto
	start := 0
	if v.Op == ir.OpCallInd {
		start = 1
	}
	var args, types []string
	floats := false
	for i, a := range v.Args[start:] {
		fl := false
		pt := intType(a.Size)
		if p != nil && i < len(p.Params) {
			fl = p.Params[i].Float
			pt = paramType(p.Params[i])
		}
		floats = floats || fl
		args = append(args, e.operand(a, fl).s)
		types = append(types, pt)
	}
	ret := retType(p)
	if v.Size == 0 {
		ret = "void"
	}
	ptypes := strings.Join(types, ", ")
	if ptypes == "" {
		ptypes = "void"
	}
	var fn string
	if v.Op == ir.OpCallInd {
		fn = fmt.Sprintf("((%s (*)(%s))%s)", ret, ptypes, wrap(e.expr(v.Args[0]), precUnary))
	} else {
		name, callee, imp := e.u.callee(v.Aux)
		switch {
		case callee != nil:
			fn = name
		case imp:
			fn = name
			im := e.u.importUse(name)
			im.callers++
			if ret != "void" && (im.ret == "" || im.ret == "void" || len(ret) > len(im.ret)) {
				im.ret = ret
			}
			key := ptypes
			im.sites[key] = true
			if floats && len(im.sites) == 1 {
				im.proto = ptypes
			} else if len(im.sites) > 1 {
				im.proto = ""
			}
		default:
			fn = fmt.Sprintf("((%s (*)(%s))%#x)", ret, ptypes, v.Aux)
		}
	}
	return fmt.Sprintf("%s(%s)", fn, strings.Join(args, ", "))
}
