package engine

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/stohirov/decompile-anything/internal/abi"
	"github.com/stohirov/decompile-anything/internal/emit"
	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/loader"
	"github.com/stohirov/decompile-anything/internal/ssa"
	"github.com/stohirov/decompile-anything/third_party/ghidra"
)

// image gives analysis read access to a Program's memory.
type image struct{ p *loader.Program }

func (m image) ReadOnly(addr uint64, size int) (uint64, bool) {
	s := m.p.Segment(addr)
	if s == nil || s.Perm&loader.PermW != 0 || s.Name == loader.ExternalSegment || size > 8 || addr+uint64(size) > s.End() {
		return 0, false
	}
	b := s.Data[addr-s.Addr : addr-s.Addr+uint64(size)]
	var buf [8]byte
	if m.p.BigEndian {
		copy(buf[8-size:], b)
		return binary.BigEndian.Uint64(buf[:]), true
	}
	copy(buf[:], b)
	return binary.LittleEndian.Uint64(buf[:]), true
}

// AddressAt reports whether a relocation in [addr, addr+size) refers to
// the object (or, for section-relative relocations, the segment) x lies
// in or next to.
func (m image) AddressAt(addr uint64, size int, x uint64) bool {
	const slack = 16
	for _, r := range m.p.RelocsIn(addr, addr+uint64(size)) {
		if !r.TargetOK {
			continue
		}
		if seg := m.p.Segment(r.Target); seg == nil || seg.Perm&loader.PermX != 0 || seg.Name == loader.ExternalSegment {
			// Code and imports: only the exact address (a function
			// pointer, with ARM's Thumb bit) is a reference.
			if x == r.Target || (x == r.Target|1 && m.p.ModeAt(r.Target) == loader.ModeThumb) {
				return true
			}
			continue
		}
		lo, hi := r.Target, r.Target+8
		if s, ok := m.p.Symbol(r.Target); ok && s.Name == r.Symbol && s.Size > 0 {
			hi = r.Target + s.Size
		} else if seg := m.p.Segment(r.Target); seg != nil {
			lo, hi = seg.Addr, seg.End()
		}
		if x+slack >= lo && x <= hi+slack {
			return true
		}
	}
	return false
}

// convention loads the calling convention of the program's default
// compiler and resolves its registers.
func (a *Analysis) convention() (*ssa.ABI, error) {
	if a.abi != nil {
		return a.abi, nil
	}
	lang, err := language(a.Program.Language)
	if err != nil {
		return nil, err
	}
	var path string
	for _, c := range lang.Compilers {
		if c.ID == "default" || c.ID == "gcc" {
			path = c.Path
			break
		}
	}
	if path == "" && len(lang.Compilers) > 0 {
		path = lang.Compilers[0].Path
	}
	if path == "" {
		return nil, fmt.Errorf("no compiler spec for %s", a.Program.Language)
	}
	proto := ""
	if strings.HasPrefix(a.Program.Language, "ARM:") && !a.Program.HardFloat {
		proto = "__stdcall_softfp"
	}
	c, err := abi.Load(ghidra.Processors, path, proto)
	if err != nil {
		return nil, err
	}
	regs := func(names []string) []ir.Varnode {
		var out []ir.Varnode
		for _, n := range names {
			if v, ok := a.lifter.Register(n); ok {
				out = append(out, v)
			}
		}
		return out
	}
	sp, ok := a.lifter.Register(c.StackPointer)
	if !ok {
		return nil, fmt.Errorf("no stack pointer register %q", c.StackPointer)
	}
	a.abi = &ssa.ABI{
		SP:           sp,
		IntParams:    regs(c.IntParams),
		FloatParams:  regs(c.FloatParams),
		IntReturns:   regs(c.IntReturns),
		FloatReturns: regs(c.FloatReturns),
		Unaffected:   regs(c.Unaffected),
		StackParams:  c.StackParams,
		StackOffset:  c.StackOffset,
		StackAlign:   c.StackAlign,
		ExtraPop:     c.ExtraPop,
	}
	return a.abi, nil
}

// Lower builds the SSA form of every function and runs prototype
// analysis across them: parameters (to a fixed point over registers passed
// on to callees), call arguments, stack promotion, results.
func (a *Analysis) Lower() (map[uint64]*ssa.Func, error) {
	if a.lowered != nil {
		return a.lowered, nil
	}
	conv, err := a.convention()
	if err != nil {
		return nil, err
	}
	img := image{a.Program}
	funcs := map[uint64]*ssa.Func{}
	evs := map[uint64]*ssa.Evidence{}
	for _, fn := range a.Functions {
		f := ssa.Build(fn, a.Arch, conv, img)
		f.Simplify(img)
		funcs[fn.Entry] = f
	}
	internal := func(t uint64) bool { return funcs[t] != nil }
	soft := func(c *ssa.Value) bool {
		s, ok := a.Program.Import(c.Aux)
		return ok && c.Op == ir.OpCall && strings.HasPrefix(s.Name, "__aeabi_")
	}
	for _, fn := range a.Functions {
		evs[fn.Entry] = funcs[fn.Entry].Gather(conv, internal, soft)
	}
	callee := func(t uint64) *ssa.Evidence { return evs[t] }
	for changed := true; changed; {
		changed = false
		for _, fn := range a.Functions {
			if evs[fn.Entry].PassThrough(callee) {
				changed = true
			}
		}
	}
	protos := map[uint64]*ssa.Proto{}
	for _, fn := range a.Functions {
		protos[fn.Entry] = &ssa.Proto{Params: evs[fn.Entry].Params(conv), Known: true}
	}
	proto := func(c *ssa.Value) *ssa.Proto {
		if c.Op == ir.OpCall {
			return protos[c.Aux]
		}
		return nil
	}
	for _, fn := range a.Functions {
		f := funcs[fn.Entry]
		f.Proto = protos[fn.Entry]
		f.BindArgs(conv, proto, soft)
		f.Simplify(img)
		if f.PromoteStack() {
			f.Simplify(img)
		}
		f.BindParams(f.Proto.Params)
	}
	// Results bottom-up over the call graph, so a caller sees what its
	// callees return; callees still pending (recursion) are guessed.
	done := map[uint64]bool{}
	known := func(c *ssa.Value) *ssa.Proto {
		if c.Op == ir.OpCall && done[c.Aux] {
			return protos[c.Aux]
		}
		return nil
	}
	var visit func(entry uint64)
	visiting := map[uint64]bool{}
	visit = func(entry uint64) {
		f := funcs[entry]
		if f == nil || done[entry] || visiting[entry] {
			return
		}
		visiting[entry] = true
		for _, c := range f.Calls() {
			if c.Op == ir.OpCall {
				visit(c.Aux)
			}
		}
		f.BindResults(conv, known)
		f.Simplify(img)
		f.SetReturns(f.InferReturns(conv))
		f.Simplify(img)
		done[entry] = true
	}
	for _, fn := range a.Functions {
		visit(fn.Entry)
	}
	a.lowered = funcs
	return funcs, nil
}

// SSA returns fn's SSA form after prototype analysis.
func (a *Analysis) SSA(fn *Function) (*ssa.Func, error) {
	funcs, err := a.Lower()
	if err != nil {
		return nil, err
	}
	return funcs[fn.Entry], nil
}

// unit prepares C output over every function.
func (a *Analysis) unit(addresses bool) (*emit.Unit, error) {
	funcs, err := a.Lower()
	if err != nil {
		return nil, err
	}
	u := &emit.Unit{Prog: a.Program, Img: image{a.Program}, Addresses: addresses}
	for _, fn := range a.Functions {
		u.Funcs = append(u.Funcs, funcs[fn.Entry])
	}
	return u, nil
}

// Decompile renders fn as C. With addresses set, each statement carries
// the address of the instruction it came from.
func (a *Analysis) Decompile(fn *Function, addresses bool) (string, error) {
	u, err := a.unit(addresses)
	if err != nil {
		return "", err
	}
	return u.Function(u.Funcs[a.index(fn)]), nil
}

// Source renders every function as one C translation unit that compiles
// for the program's target, with the data the code references.
func (a *Analysis) Source(addresses bool) (string, error) {
	u, err := a.unit(addresses)
	if err != nil {
		return "", err
	}
	return u.Source(u.Funcs), nil
}

func (a *Analysis) index(fn *Function) int {
	for i, f := range a.Functions {
		if f == fn {
			return i
		}
	}
	return -1
}
