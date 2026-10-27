package sleigh

// P-code templates: a constructor's semantics with placeholders that are
// filled in from the matched instruction (Ghidra's semantics.hh).

// pcodeOp is a raw P-code opcode, numbered as Ghidra's CPUI_* enum.
type pcodeOp int

// Template-only directives reuse opcodes that never appear in templates.
const (
	opBuild      pcodeOp = 60 // CPUI_MULTIEQUAL: build an operand's semantics
	opDelaySlot  pcodeOp = 61 // CPUI_INDIRECT
	opCrossBuild pcodeOp = 66 // CPUI_PTRSUB
	opMacroBuild pcodeOp = 64 // CPUI_CAST
	opLabelBuild pcodeOp = 65 // CPUI_PTRADD: place a label
)

type constKind uint8

const (
	ctReal constKind = iota
	ctHandle
	ctStart
	ctNext
	ctNext2
	ctCurSpace
	ctCurSpaceSize
	ctSpaceID
	ctRelative
	ctFlowRef
	ctFlowRefSize
	ctFlowDest
	ctFlowDestSize
)

// Selectors of the part of a handle a ctHandle constant reads.
const (
	vSpace = iota
	vOffset
	vSize
	vOffsetPlus
)

type constTpl struct {
	kind   constKind
	real   uint64
	space  *Space
	handle int
	sel    int
}

// fix returns the constant's value for the instruction w is walking.
// Address spaces are returned by index.
func (c constTpl) fix(w *walker) uint64 {
	switch c.kind {
	case ctStart:
		return w.ctx.addr
	case ctNext:
		return w.naddr()
	case ctNext2:
		return w.n2addr()
	case ctCurSpace:
		return uint64(w.ctx.spec.DefaultSpace.Index)
	case ctCurSpaceSize:
		return uint64(w.ctx.spec.DefaultSpace.Size)
	case ctFlowRef, ctFlowDest:
		return 0 // only meaningful during p-code injection
	case ctFlowRefSize, ctFlowDestSize:
		return uint64(w.ctx.spec.DefaultSpace.Size)
	case ctSpaceID:
		return uint64(c.space.Index)
	case ctHandle:
		h := &w.point.resolve[c.handle].hand
		switch c.sel {
		case vSpace:
			if h.offsetSpace == nil {
				return uint64(h.space.Index)
			}
			return uint64(h.tempSpace.Index)
		case vOffset:
			if h.offsetSpace == nil {
				return h.offsetOffset
			}
			return h.tempOffset
		case vSize:
			return uint64(h.size)
		case vOffsetPlus:
			v := h.offsetOffset
			if h.offsetSpace != nil {
				v = h.tempOffset
			}
			if h.space != w.ctx.spec.constSpace {
				return v + c.real&0xffff // offset of a truncated varnode
			}
			return v >> (8 * (c.real >> 16)) // a constant, shifted
		}
	}
	return c.real // ctReal, ctRelative
}

// fixSpace returns the address space the constant names.
func (c constTpl) fixSpace(w *walker) *Space {
	switch c.kind {
	case ctCurSpace:
		return w.ctx.spec.DefaultSpace
	case ctSpaceID:
		return c.space
	case ctFlowRef:
		return w.ctx.spec.DefaultSpace
	case ctHandle:
		if c.sel == vSpace {
			h := &w.point.resolve[c.handle].hand
			if h.offsetSpace == nil {
				if h.space == nil {
					// The operand's constructor exports nothing, so there
					// is no varnode to use (a spec bug Ghidra hits as a
					// null handle).
					badData(w, "operand %d exports no varnode", c.handle)
				}
				return h.space
			}
			return h.tempSpace
		}
	}
	badData(w, "constant template is not an address space")
	return nil
}

type varnodeTpl struct {
	space, offset, size constTpl
}

// dynamic reports whether the varnode is reached through a pointer
// computed at run time (a handle whose offset lives in another varnode).
func (v *varnodeTpl) dynamic(w *walker) bool {
	return v.offset.kind == ctHandle && w.point.resolve[v.offset.handle].hand.offsetSpace != nil
}

// handleTpl is what a constructor exports to its parent.
type handleTpl struct {
	space, size                  constTpl
	ptrSpace, ptrOffset, ptrSize constTpl
	tempSpace, tempOffset        constTpl
}

func (t *handleTpl) fix(h *handle, w *walker) {
	if t.ptrSpace.kind == ctReal {
		// Static varnode: fill in space and offset, possibly inherited
		// whole from a sub-constructor's handle.
		switch {
		case t.space.kind == ctHandle && t.space.sel == vSpace:
			h.space = w.point.resolve[t.space.handle].hand.space
		default:
			h.space = t.space.fixSpace(w)
		}
		h.size = int(t.size.fix(w))
		if t.ptrOffset.kind == ctHandle {
			o := &w.point.resolve[t.ptrOffset.handle].hand
			h.offsetSpace, h.offsetOffset, h.offsetSize = o.offsetSpace, o.offsetOffset, o.offsetSize
			h.tempSpace, h.tempOffset = o.tempSpace, o.tempOffset
		} else {
			h.offsetSpace = nil
			h.offsetOffset = h.space.wrap(t.ptrOffset.fix(w))
		}
		return
	}
	h.space = t.space.fixSpace(w)
	h.size = int(t.size.fix(w))
	h.offsetOffset = t.ptrOffset.fix(w)
	h.offsetSpace = t.ptrSpace.fixSpace(w)
	if h.offsetSpace.Kind == SpaceConstant {
		// A pointer that is a constant is a static address.
		h.offsetSpace = nil
		h.offsetOffset = h.space.wrap(h.offsetOffset * uint64(h.space.WordSize))
		return
	}
	h.offsetSize = int(t.ptrSize.fix(w))
	h.tempSpace = t.tempSpace.fixSpace(w)
	h.tempOffset = t.tempOffset.fix(w)
}

type opTpl struct {
	code pcodeOp
	out  *varnodeTpl
	in   []*varnodeTpl
}

type constructTpl struct {
	delaySlot int
	numLabels int
	result    *handleTpl
	ops       []*opTpl
}
