// Package ssa holds a function in static single assignment form: every
// value is defined once and refers to the values it uses directly. The
// decompiler builds it from a function's IR CFG, simplifies it, turns stack
// accesses into variables, infers the prototype, and hands the result to
// structuring and C emission.
//
// Registers, P-code temporaries and promoted stack slots are renamed into
// SSA with dominance frontiers (Cytron et al.). Memory stays as ordered
// LOAD, STORE and CALL values inside each block.
package ssa

import (
	"fmt"
	"sort"
	"strings"

	"github.com/stohirov/decompile-anything/internal/ir"
)

// Op is an IR opcode or one of the SSA-only pseudo-ops below.
type Op = ir.Opcode

// Pseudo-ops, numbered past the IR's opcodes.
const (
	// OpConst is a constant; Aux holds the value.
	OpConst Op = 200 + iota
	// OpInput is a variable's value on entry to the function.
	OpInput
	// OpUndef is a value nothing defined, such as a register a call clobbered.
	OpUndef
	// OpCallOut is the value a call leaves in a register: Args[0] is the
	// call, Var the register. Prototype analysis replaces it.
	OpCallOut
	// OpRead and OpWrite access a Var before renaming removes them.
	OpRead
	OpWrite
)

// OpName names op, including pseudo-ops.
func OpName(op Op) string {
	switch op {
	case OpConst:
		return "CONST"
	case OpInput:
		return "INPUT"
	case OpUndef:
		return "UNDEF"
	case OpCallOut:
		return "CALLOUT"
	case OpRead:
		return "READ"
	case OpWrite:
		return "WRITE"
	}
	return op.String()
}

// Var is a storage location renamed into SSA: a register, a temporary, or
// a stack slot at Offset from the stack pointer's value on entry.
type Var struct {
	Space  ir.SpaceID
	Offset int64
	Size   int
	Name   string
}

func (v *Var) String() string {
	if v.Name != "" {
		return v.Name
	}
	if v.Space == ir.SpaceStack {
		if v.Offset < 0 {
			return fmt.Sprintf("stack_m%x", -v.Offset)
		}
		return fmt.Sprintf("stack_%x", v.Offset)
	}
	return fmt.Sprintf("%s_%x", v.Space, v.Offset)
}

// Value is one SSA value: an operation over other values.
//
// Size is the result's size in bytes, 0 for none. Loads, stores and calls
// keep IR conventions: Aux of LOAD and STORE is the space accessed, Args
// are the address (and the stored value). A direct CALL has its target in
// Aux and its arguments in Args; CALLIND has the target first. CALLOTHER
// holds the user-op index in Aux.
type Value struct {
	ID     int
	Op     Op
	Size   int
	Args   []*Value
	Aux    uint64
	Var    *Var // OpInput, OpRead, OpWrite, OpCallOut, and the variable a PHI joins
	Block  *Block
	Origin uint64
	// Addr marks a constant that is an address in the program (it came
	// from relocated bytes), so output names the symbol it points into.
	Addr bool
	// Call describes CALL and CALLIND values.
	Call *Call
}

// BlockKind is how a block ends.
type BlockKind uint8

const (
	BlockPlain  BlockKind = iota // continues at Succs[0]
	BlockIf                      // Control picks Succs[1] when true, Succs[0] when false
	BlockSwitch                  // Control is a jump target; Cases map values to Succs
	BlockReturn                  // returns Results
	BlockStop                    // flow stops: undecodable code, or a jump nothing resolved
)

// Block is a basic block. Phis come first in Values; the other values run
// in order.
type Block struct {
	ID      int
	Start   uint64
	Kind    BlockKind
	Values  []*Value
	Control *Value
	Succs   []*Block
	Preds   []*Block
	// Cases holds, for BlockSwitch, the jump's target address per case.
	Cases []ir.JumpCase
	// Results are the values a BlockReturn returns, one per entry of the
	// function's Returns; before prototype analysis, every return register.
	Results []*Value
	// End is the address of the block's last instruction.
	End uint64
}

// Func is a function in SSA form.
type Func struct {
	Name   string
	Entry  uint64
	Arch   *ir.Arch
	Blocks []*Block // Blocks[0] is the entry
	// Params are the function's parameters as OpInput values, in the
	// order of Proto.Params.
	Params []*Value
	// Proto is the inferred prototype, once prototype analysis ran.
	Proto    *Proto
	Warnings []ir.Warning

	// RetRegs are the registers Results read before prototype analysis.
	RetRegs []ir.Varnode
	// SP is the stack pointer's variable.
	SP *Var

	insns map[uint64]int // instruction lengths by address

	nextValue, nextBlock int
	consts               map[[3]uint64]*Value
	inputs               map[*Var]*Value
}

// NewValue appends a value to b (or leaves it outside any block when b is
// nil).
func (f *Func) NewValue(b *Block, op Op, size int, origin uint64, args ...*Value) *Value {
	v := f.newValue(op, size, origin, args...)
	if b != nil {
		v.Block = b
		b.Values = append(b.Values, v)
	}
	return v
}

func (f *Func) newValue(op Op, size int, origin uint64, args ...*Value) *Value {
	f.nextValue++
	return &Value{ID: f.nextValue, Op: op, Size: size, Origin: origin, Args: args}
}

// Const returns the shared constant value x of size bytes.
func (f *Func) Const(x uint64, size int) *Value { return f.constant(x, size, false) }

// AddrConst returns the shared constant x marked as an address.
func (f *Func) AddrConst(x uint64, size int) *Value { return f.constant(x, size, true) }

func (f *Func) constant(x uint64, size int, addr bool) *Value {
	x &= ir.Mask(size)
	key := [3]uint64{x, uint64(size), 0}
	if addr {
		key[2] = 1
	}
	if v := f.consts[key]; v != nil {
		return v
	}
	if f.consts == nil {
		f.consts = map[[3]uint64]*Value{}
	}
	v := f.newValue(OpConst, size, 0)
	v.Aux, v.Addr = x, addr
	f.consts[key] = v
	return v
}

// Input returns the value var holds on entry.
func (f *Func) Input(v *Var) *Value {
	if in := f.inputs[v]; in != nil {
		return in
	}
	if f.inputs == nil {
		f.inputs = map[*Var]*Value{}
	}
	in := f.newValue(OpInput, v.Size, f.Entry)
	in.Var = v
	f.inputs[v] = in
	return in
}

// NewBlock adds an empty block.
func (f *Func) NewBlock(kind BlockKind) *Block {
	f.nextBlock++
	b := &Block{ID: f.nextBlock, Kind: kind}
	f.Blocks = append(f.Blocks, b)
	return b
}

func (f *Func) warn(addr uint64, format string, args ...any) {
	f.Warnings = append(f.Warnings, ir.Warning{Addr: addr, Msg: fmt.Sprintf(format, args...)})
}

// IsConst reports whether v is a constant, and its value.
func (v *Value) IsConst() (uint64, bool) {
	if v.Op == OpConst {
		return v.Aux, true
	}
	return 0, false
}

// HasEffect reports whether v must run even when nothing uses its result.
func (v *Value) HasEffect() bool {
	switch v.Op {
	case ir.OpStore, ir.OpCall, ir.OpCallInd, ir.OpCallOther, OpWrite:
		return true
	}
	return false
}

// reset replaces v's operation in place.
func (v *Value) reset(op Op, args ...*Value) {
	v.Op = op
	v.Args = append(v.Args[:0:0], args...)
	v.Aux = 0
	v.Addr = false
}

// copyOf turns v into a copy of x, which a later pass forwards to v's uses.
func (v *Value) copyOf(x *Value) { v.reset(ir.OpCopy, x) }

// removeValues drops the values of b for which drop returns true.
func (b *Block) removeValues(drop func(*Value) bool) {
	out := b.Values[:0]
	for _, v := range b.Values {
		if !drop(v) {
			out = append(out, v)
		}
	}
	clear(b.Values[len(out):])
	b.Values = out
}

// predIndex returns the position of p in b.Preds.
func (b *Block) predIndex(p *Block) int {
	for i, q := range b.Preds {
		if q == p {
			return i
		}
	}
	return -1
}

// String prints the function, one value per line, for tests and debugging.
func (f *Func) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s(", f.Name)
	for i, p := range f.Params {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(f.ValueName(p))
	}
	sb.WriteString(")")
	if f.Proto != nil && len(f.Proto.Returns) > 0 {
		sb.WriteString(" ->")
		for _, r := range f.Proto.Returns {
			fmt.Fprintf(&sb, " %d", r.Size)
		}
	}
	sb.WriteString("\n")
	for _, b := range f.Blocks {
		fmt.Fprintf(&sb, "b%d at %#x:", b.ID, b.Start)
		if len(b.Preds) > 0 {
			sb.WriteString(" <-")
			for _, p := range b.Preds {
				fmt.Fprintf(&sb, " b%d", p.ID)
			}
		}
		sb.WriteString("\n")
		for _, v := range b.Values {
			fmt.Fprintf(&sb, "    %s\n", f.Format(v))
		}
		switch b.Kind {
		case BlockPlain:
			fmt.Fprintf(&sb, "    goto b%d\n", b.Succs[0].ID)
		case BlockIf:
			fmt.Fprintf(&sb, "    if %s goto b%d else b%d\n", f.ValueName(b.Control), b.Succs[1].ID, b.Succs[0].ID)
		case BlockSwitch:
			fmt.Fprintf(&sb, "    switch %s:", f.ValueName(b.Control))
			for _, s := range b.Succs {
				fmt.Fprintf(&sb, " b%d", s.ID)
			}
			sb.WriteString("\n")
		case BlockReturn:
			sb.WriteString("    return")
			for i, r := range b.Results {
				if i > 0 {
					sb.WriteString(",")
				}
				fmt.Fprintf(&sb, " %s", f.ValueName(r))
			}
			sb.WriteString("\n")
		case BlockStop:
			sb.WriteString("    stop\n")
		}
	}
	return sb.String()
}

// ValueName prints a reference to v.
func (f *Func) ValueName(v *Value) string {
	if v == nil {
		return "<nil>"
	}
	switch v.Op {
	case OpConst:
		if v.Addr {
			return fmt.Sprintf("&%#x", v.Aux)
		}
		return fmt.Sprintf("%#x:%d", v.Aux, v.Size)
	case OpInput:
		return v.Var.String() + "_in"
	}
	return fmt.Sprintf("v%d", v.ID)
}

// Format prints v as "vN:size = OP args".
func (f *Func) Format(v *Value) string {
	var sb strings.Builder
	if v.Size > 0 {
		fmt.Fprintf(&sb, "%s:%d = ", f.ValueName(v), v.Size)
	}
	sb.WriteString(OpName(v.Op))
	switch v.Op {
	case ir.OpLoad, ir.OpStore:
		fmt.Fprintf(&sb, " %s", ir.SpaceID(v.Aux))
	case ir.OpCall:
		fmt.Fprintf(&sb, " %#x", v.Aux)
	case ir.OpCallOther:
		if f.Arch != nil && int(v.Aux) < len(f.Arch.UserOps) {
			fmt.Fprintf(&sb, " %s", f.Arch.UserOps[v.Aux])
		}
	case OpRead, OpWrite, OpCallOut, OpUndef:
		if v.Var != nil {
			fmt.Fprintf(&sb, " %s", v.Var)
		}
	}
	for i, a := range v.Args {
		if i > 0 || v.Op == ir.OpLoad || v.Op == ir.OpStore || v.Op == ir.OpCall || v.Op == ir.OpCallOther || v.Var != nil {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, " %s", f.ValueName(a))
		if v.Op == ir.OpPhi && v.Block != nil && i < len(v.Block.Preds) {
			fmt.Fprintf(&sb, "(b%d)", v.Block.Preds[i].ID)
		}
	}
	return sb.String()
}

// sortBlocks orders blocks by address, keeping the entry first.
func (f *Func) sortBlocks() {
	rest := f.Blocks[1:]
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].Start < rest[j].Start })
}

// SplitCriticalEdges puts an empty block on every edge from a block with
// several successors to a block with several predecessors, so the copies
// leaving SSA form have a block of their own to live in.
func (f *Func) SplitCriticalEdges() {
	for _, b := range append([]*Block{}, f.Blocks...) {
		if len(b.Succs) < 2 {
			continue
		}
		for i, s := range b.Succs {
			if len(s.Preds) < 2 {
				continue
			}
			n := f.NewBlock(BlockPlain)
			n.Start, n.End = s.Start, s.Start
			n.Succs = []*Block{s}
			n.Preds = []*Block{b}
			b.Succs[i] = n
			if j := s.predIndex(b); j >= 0 {
				s.Preds[j] = n
			}
		}
	}
}

// insnLen returns the length of the instruction at addr, or 1.
func (f *Func) insnLen(addr uint64) int {
	if n := f.insns[addr]; n > 0 {
		return n
	}
	return 1
}
