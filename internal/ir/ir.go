// Package ir is the architecture-neutral intermediate representation every
// analysis pass runs on. It starts as a near copy of SLEIGH P-code and gains
// structure (SSA, stack slots, types) as passes run.
package ir

import "fmt"

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
type Op struct {
	Code   Opcode
	Out    *Varnode
	In     []Varnode
	Origin uint64 // source instruction address; powers evidence links in output
}

// Block is a straight run of ops with one entry and one exit.
type Block struct {
	Start uint64
	Ops   []Op
	Succ  []*Block
	Pred  []*Block
}

// Function is a CFG of blocks plus what analysis has learned about it.
type Function struct {
	Entry  uint64
	Name   string
	Blocks []*Block
}
