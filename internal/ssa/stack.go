package ssa

import (
	"github.com/stohirov/decompile-anything/internal/ir"
)

// Stack analysis tracks the stack pointer as an offset from its value on
// entry. Once simplification has folded the arithmetic, every stack
// address is SP_in + constant, so loads and stores through such addresses
// name fixed slots of the frame (negative offsets on a descending stack)
// or of the caller's outgoing arguments (from the convention's stack
// parameter offset up).

// Frame is what stack analysis learned about a function.
type Frame struct {
	Accesses []Access
	// Escapes holds a value that uses a stack address other than as the
	// address of a load or store: the frame's memory is visible beyond
	// this function's own accesses and must stay memory.
	Escapes *Value
}

// Access is a load or store at a constant stack offset.
type Access struct {
	Offset int64
	Size   int
	V      *Value
}

// SPOffset returns v's offset from the stack pointer's entry value, when v
// is the entry value plus a constant.
func (f *Func) SPOffset(v *Value) (int64, bool) {
	if f.SP == nil {
		return 0, false
	}
	var off int64
	for range 16 {
		switch {
		case v.Op == OpInput && v.Var == f.SP:
			return off, true
		case v.Op == ir.OpIntAdd && v.Args[1].Op == OpConst:
			off += ir.SignExtend(v.Args[1].Aux, v.Size)
			v = v.Args[0]
		case v.Op == ir.OpCopy:
			v = v.Args[0]
		default:
			return 0, false
		}
	}
	return 0, false
}

// Frame scans f for stack accesses and escaping stack addresses.
func (f *Func) Frame() *Frame {
	fr := &Frame{}
	escape := func(v *Value) {
		if fr.Escapes == nil {
			fr.Escapes = v
		}
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for i, a := range v.Args {
				off, ok := f.SPOffset(a)
				if !ok {
					continue
				}
				switch {
				case (v.Op == ir.OpLoad || v.Op == ir.OpStore) && i == 0 && ir.SpaceID(v.Aux) == ir.SpaceRAM:
					size := v.Size
					if v.Op == ir.OpStore {
						size = v.Args[1].Size
					}
					fr.Accesses = append(fr.Accesses, Access{Offset: off, Size: size, V: v})
				case v.Op == ir.OpIntAdd && i == 0 && v.Args[1].Op == OpConst:
					// Another stack address; its own uses are checked.
				case v.Call != nil && v.Call.NArgs < 0 && i == len(v.Args)-1:
					// The stack pointer a callee starts with.
				default:
					escape(v)
				}
			}
		}
		if b.Control != nil {
			if _, ok := f.SPOffset(b.Control); ok {
				escape(b.Control)
			}
		}
		for _, r := range b.Results {
			if _, ok := f.SPOffset(r); ok {
				escape(r)
			}
		}
	}
	return fr
}

// PromoteStack turns the frame's loads and stores into variables renamed
// into SSA, unless a stack address escapes. Stack slots read before any
// write become inputs: stack parameters, or uninitialized locals.
func (f *Func) PromoteStack() bool {
	fr := f.Frame()
	if fr.Escapes != nil || len(fr.Accesses) == 0 {
		return false
	}
	var rs [][2]int64
	at := map[*Value]Access{}
	for _, a := range fr.Accesses {
		rs = append(rs, [2]int64{a.Offset, a.Offset + int64(a.Size)})
		at[a.V] = a
	}
	bd := &builder{f: f, arch: f.Arch, vars: map[ir.SpaceID][]*Var{
		ir.SpaceStack: atomize(ir.SpaceStack, rs, func(int64, int) string { return "" }),
	}}
	for _, b := range f.Blocks {
		old := b.Values
		b.Values = make([]*Value, 0, len(old))
		for _, v := range old {
			a, ok := at[v]
			if !ok {
				b.Values = append(b.Values, v)
				continue
			}
			vn := ir.Varnode{Space: ir.SpaceStack, Offset: uint64(a.Offset), Size: uint8(a.Size)}
			if v.Op == ir.OpLoad {
				r := bd.read(b, vn, v.Origin)
				v.copyOf(r)
				b.Values = append(b.Values, v)
			} else {
				bd.write(b, vn, v.Args[1], v.Origin)
			}
		}
	}
	f.rename()
	return true
}
