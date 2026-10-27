// Package ir is the architecture-neutral intermediate representation every
// analysis pass runs on. It starts as a near copy of SLEIGH P-code and gains
// structure (SSA, stack slots, types) as passes run.
package ir

import (
	"fmt"
	"strings"
)

// SpaceID names an address space a Varnode lives in.
type SpaceID uint8

const (
	SpaceConst    SpaceID = iota // literal values; Offset holds the constant
	SpaceRAM                     // loaded program memory
	SpaceRegister                // processor registers, as laid out by the .sla spec
	SpaceUnique                  // P-code temporaries
	SpaceStack                   // local slots, added by stack analysis
)

func (s SpaceID) String() string {
	switch s {
	case SpaceConst:
		return "const"
	case SpaceRAM:
		return "ram"
	case SpaceRegister:
		return "register"
	case SpaceUnique:
		return "unique"
	case SpaceStack:
		return "stack"
	}
	return fmt.Sprintf("space(%d)", uint8(s))
}

// Varnode is a sized slice of an address space: (space, offset, size).
type Varnode struct {
	Space  SpaceID
	Offset uint64
	Size   uint8
}

func (v Varnode) String() string {
	return fmt.Sprintf("(%s, %#x, %d)", v.Space, v.Offset, v.Size)
}

// Op is one IR operation with zero or one output and N inputs.
//
// Ops keep P-code's conventions: a branch target in the ram space is the
// address itself, not memory at it; a BRANCH or CBRANCH whose target is a
// constant jumps that many ops forward or back within the same instruction;
// the first input of LOAD and STORE is a constant holding the SpaceID
// accessed; and the first input of CALLOTHER is a constant indexing
// Arch.UserOps.
type Op struct {
	Code   Opcode
	Out    *Varnode
	In     []Varnode
	Origin uint64 // source instruction address; powers evidence links in output
}

// Insn is one decoded machine instruction and the IR it lifts to.
type Insn struct {
	Addr uint64
	// Length runs to the next instruction control falls through to. It
	// includes delay slots, whose ops are part of Ops.
	Length int
	Bytes  []byte
	Text   string
	Ops    []Op
}

// Block is a straight run of ops with one entry and one exit.
//
// Successor order is fixed by the last op. After CBRANCH, Succ[0] is the
// fall-through and Succ[1] the taken branch. After BRANCHIND, Succ holds the
// resolved targets. A block whose BRANCH leaves the function (a tail call)
// has no successors; a conditional exit gets a block of its own holding
// that BRANCH.
type Block struct {
	Start uint64 // Origin of the first op
	Ops   []Op
	Succ  []*Block
	Pred  []*Block
}

// Function is a CFG of blocks plus what analysis has learned about it.
// Blocks[0] is the entry block; the rest are sorted by address.
type Function struct {
	Entry      uint64
	Name       string
	Blocks     []*Block
	Insns      []*Insn     // every instruction in the function, by address
	JumpTables []JumpTable // resolved indirect jumps
	Unresolved []uint64    // indirect jumps whose targets are unknown
	Calls      []uint64    // direct call and tail-call targets, sorted
	Warnings   []Warning
}

// JumpTable is an indirect jump with the targets analysis proved for it.
type JumpTable struct {
	Addr  uint64 // the jumping instruction
	Cases []JumpCase
}

// JumpCase maps one value of the switch variable to its target.
type JumpCase struct {
	Value  int64
	Target uint64
}

// Warning records something analysis could not handle at an address.
type Warning struct {
	Addr uint64
	Msg  string
}

func (w Warning) String() string { return fmt.Sprintf("%#x: %s", w.Addr, w.Msg) }

// Arch describes the processor IR was lifted from, for printing and for
// passes that need register names or byte order.
type Arch struct {
	Language    string // SLEIGH language id
	BigEndian   bool
	PointerSize int
	UserOps     []string // CALLOTHER names, by index
	// Register names a register varnode, or returns "" when no register
	// covers exactly that range.
	Register func(offset uint64, size uint8) string
}

// FormatVarnode prints v with register names and constants in hex.
func (a *Arch) FormatVarnode(v Varnode) string {
	switch v.Space {
	case SpaceConst:
		return fmt.Sprintf("%#x:%d", v.Offset, v.Size)
	case SpaceRegister:
		if a != nil && a.Register != nil {
			if name := a.Register(v.Offset, v.Size); name != "" {
				return name
			}
		}
	case SpaceUnique:
		return fmt.Sprintf("u%x:%d", v.Offset, v.Size)
	}
	return v.String()
}

// FormatOp prints op as "out = OPCODE in, in".
func (a *Arch) FormatOp(op Op) string {
	var b strings.Builder
	if op.Out != nil {
		fmt.Fprintf(&b, "%s = ", a.FormatVarnode(*op.Out))
	}
	b.WriteString(op.Code.String())
	for i, in := range op.In {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte(' ')
		switch {
		case i == 0 && (op.Code == OpLoad || op.Code == OpStore) && in.Space == SpaceConst:
			b.WriteString(SpaceID(in.Offset).String())
		case i == 0 && op.Code == OpCallOther && in.Space == SpaceConst && a != nil && int(in.Offset) < len(a.UserOps):
			b.WriteString(a.UserOps[in.Offset])
		case i == 0 && in.Space == SpaceRAM && isFlow(op.Code):
			fmt.Fprintf(&b, "%#x", in.Offset)
		default:
			b.WriteString(a.FormatVarnode(in))
		}
	}
	return b.String()
}

func isFlow(c Opcode) bool {
	return c == OpBranch || c == OpCBranch || c == OpCall
}
