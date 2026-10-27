// Package irexec interprets IR functions on concrete values by walking
// their control-flow graphs. Tests use it to check the lifter and CFG
// construction against native execution; it is not part of the analysis
// pipeline and does not emulate a device.
package irexec

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/stohirov/decompile-anything/internal/ir"
)

// ErrUnsupported reports IR the interpreter cannot execute.
var ErrUnsupported = errors.New("unsupported by the IR interpreter")

// Hook stands in for code at an address: an external function or a
// callback. It reads arguments from and writes results to the machine.
type Hook func(m *Machine) error

// UserOp computes the result of a CALLOTHER from its inputs (without the
// leading op index) and the output's current value, which some specs
// expect the operation to update (accumulating vector ops).
type UserOp func(in []uint64, sizes []int, old uint64, outSize int) (uint64, error)

const pageBits = 12

type page [1 << pageBits]byte

// Machine holds memory for every address space and the functions it runs.
type Machine struct {
	Arch  *ir.Arch
	Funcs map[uint64]*ir.Function
	Hooks map[uint64]Hook
	// UserOps gives semantics to CALLOTHER operations with a result, by
	// name. SLEIGH specs leave them opaque, so the caller supplies them.
	UserOps   map[string]UserOp
	StepLimit int // ops to run before giving up; 0 means no limit
	Steps     int
	mem       [ir.SpaceStack + 1]map[uint64]*page
	depth     int
}

const maxDepth = 10000

// New returns a machine with empty memory that runs fns.
func New(arch *ir.Arch, fns []*ir.Function) *Machine {
	m := &Machine{Arch: arch, Funcs: map[uint64]*ir.Function{}, Hooks: map[uint64]Hook{}, UserOps: map[string]UserOp{}}
	for _, fn := range fns {
		m.Funcs[fn.Entry] = fn
	}
	for i := range m.mem {
		m.mem[i] = map[uint64]*page{}
	}
	return m
}

func (m *Machine) page(space ir.SpaceID, addr uint64) (*page, error) {
	if int(space) >= len(m.mem) || space == ir.SpaceConst {
		return nil, fmt.Errorf("memory access to %s space: %w", space, ErrUnsupported)
	}
	p := m.mem[space][addr>>pageBits]
	if p == nil {
		p = new(page)
		m.mem[space][addr>>pageBits] = p
	}
	return p, nil
}

// ReadBytes copies n bytes of space starting at addr.
func (m *Machine) ReadBytes(space ir.SpaceID, addr uint64, n int) ([]byte, error) {
	out := make([]byte, n)
	for i := range n {
		a := addr + uint64(i)
		p, err := m.page(space, a)
		if err != nil {
			return nil, err
		}
		out[i] = p[a&(1<<pageBits-1)]
	}
	return out, nil
}

// WriteBytes stores b in space starting at addr.
func (m *Machine) WriteBytes(space ir.SpaceID, addr uint64, b []byte) error {
	for i, x := range b {
		a := addr + uint64(i)
		p, err := m.page(space, a)
		if err != nil {
			return err
		}
		p[a&(1<<pageBits-1)] = x
	}
	return nil
}

// Load reads a size-byte integer in the machine's byte order.
func (m *Machine) Load(space ir.SpaceID, addr uint64, size int) (uint64, error) {
	if size > 8 {
		return 0, fmt.Errorf("%d-byte value: %w", size, ErrUnsupported)
	}
	b, err := m.ReadBytes(space, addr, size)
	if err != nil {
		return 0, err
	}
	var v uint64
	for i := range size {
		if m.Arch.BigEndian {
			v = v<<8 | uint64(b[i])
		} else {
			v |= uint64(b[i]) << (8 * i)
		}
	}
	return v, nil
}

// Store writes a size-byte integer in the machine's byte order.
func (m *Machine) Store(space ir.SpaceID, addr uint64, size int, v uint64) error {
	b := make([]byte, size)
	for i := range size {
		shift := 8 * i
		if m.Arch.BigEndian {
			shift = 8 * (size - 1 - i)
		}
		if shift < 64 {
			b[i] = byte(v >> shift)
		}
	}
	return m.WriteBytes(space, addr, b)
}

// Get returns the value of a varnode of up to 8 bytes.
func (m *Machine) Get(v ir.Varnode) (uint64, error) {
	if v.Space == ir.SpaceConst {
		return v.Offset & ir.Mask(int(v.Size)), nil
	}
	return m.Load(v.Space, v.Offset, int(v.Size))
}

// Set assigns a varnode of up to 8 bytes.
func (m *Machine) Set(v ir.Varnode, x uint64) error {
	if v.Space == ir.SpaceConst {
		return fmt.Errorf("write to a constant: %w", ErrUnsupported)
	}
	if v.Size > 8 {
		return fmt.Errorf("%d-byte value: %w", v.Size, ErrUnsupported)
	}
	return m.Store(v.Space, v.Offset, int(v.Size), x)
}

// Call runs the hook or function at addr until it returns.
func (m *Machine) Call(addr uint64) error {
	if h, ok := m.Hooks[addr]; ok {
		return h(m)
	}
	fn, ok := m.Funcs[addr]
	if !ok {
		return fmt.Errorf("call to %#x: no function or hook there", addr)
	}
	if m.depth++; m.depth > maxDepth {
		return fmt.Errorf("call depth over %d", maxDepth)
	}
	defer func() { m.depth-- }()
	return m.run(fn)
}

func (m *Machine) run(fn *ir.Function) error {
	if len(fn.Blocks) == 0 {
		return fmt.Errorf("%s has no code", fn.Name)
	}
	b := fn.Blocks[0]
	for {
		for i, op := range b.Ops {
			if m.Steps++; m.StepLimit > 0 && m.Steps > m.StepLimit {
				return fmt.Errorf("step limit of %d reached in %s", m.StepLimit, fn.Name)
			}
			last := i == len(b.Ops)-1
			switch op.Code {
			case ir.OpBranch:
				if len(b.Succ) == 1 {
					b = b.Succ[0]
					break
				}
				if op.In[0].Space != ir.SpaceRAM {
					return fmt.Errorf("%#x: relative branch leaves its block", op.Origin)
				}
				return m.Call(op.In[0].Offset) // tail call
			case ir.OpCBranch:
				c, err := m.Get(op.In[1])
				if err != nil {
					return err
				}
				if len(b.Succ) != 2 {
					return fmt.Errorf("%#x: CBRANCH block has %d successors", op.Origin, len(b.Succ))
				}
				b = b.Succ[c&1]
			case ir.OpBranchInd:
				t, err := m.Get(op.In[0])
				if err != nil {
					return err
				}
				next := (*ir.Block)(nil)
				for _, s := range b.Succ {
					if s.Start == t {
						next = s
					}
				}
				if next == nil {
					if len(b.Succ) > 0 {
						return fmt.Errorf("%#x: indirect jump to %#x is not in its jump table", op.Origin, t)
					}
					return m.Call(t) // unresolved: an indirect tail call
				}
				b = next
			case ir.OpReturn:
				return nil
			default:
				if err := m.exec(op); err != nil {
					return fmt.Errorf("%#x: %s: %w", op.Origin, m.Arch.FormatOp(op), err)
				}
				if !last {
					continue
				}
				if len(b.Succ) != 1 {
					return fmt.Errorf("%#x: control flow stops after %s", op.Origin, m.Arch.FormatOp(op))
				}
				b = b.Succ[0]
			}
			break // the block's last op chose the next block
		}
	}
}

// exec runs one op that does not end a block.
func (m *Machine) exec(op ir.Op) error {
	switch op.Code {
	case ir.OpLoad:
		if ir.SpaceID(op.In[0].Offset) == ir.SpaceConst {
			// Loading from the constant space yields the address itself.
			b, err := m.value(op.In[1])
			if err != nil {
				return err
			}
			v := m.toBig(b)
			v.And(v, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 8*uint(op.Out.Size)), big.NewInt(1)))
			return m.WriteBytes(op.Out.Space, op.Out.Offset, m.fromBig(v, int(op.Out.Size)))
		}
		addr, err := m.Get(op.In[1])
		if err != nil {
			return err
		}
		b, err := m.ReadBytes(ir.SpaceID(op.In[0].Offset), addr, int(op.Out.Size))
		if err != nil {
			return err
		}
		return m.WriteBytes(op.Out.Space, op.Out.Offset, b)
	case ir.OpStore:
		addr, err := m.Get(op.In[1])
		if err != nil {
			return err
		}
		b, err := m.value(op.In[2])
		if err != nil {
			return err
		}
		return m.WriteBytes(ir.SpaceID(op.In[0].Offset), addr, b)
	case ir.OpCall:
		return m.Call(op.In[0].Offset)
	case ir.OpCallInd:
		t, err := m.Get(op.In[0])
		if err != nil {
			return err
		}
		return m.Call(t)
	case ir.OpCallOther:
		if op.Out == nil {
			return nil // hints, barriers and mode switches change no IR state
		}
		name := fmt.Sprintf("userop%d", op.In[0].Offset)
		if int(op.In[0].Offset) < len(m.Arch.UserOps) {
			name = m.Arch.UserOps[op.In[0].Offset]
		}
		f := m.UserOps[name]
		if f == nil {
			return fmt.Errorf("user op %s with a result: %w", name, ErrUnsupported)
		}
		in := make([]uint64, len(op.In)-1)
		sizes := make([]int, len(op.In)-1)
		for i, v := range op.In[1:] {
			x, err := m.Get(v)
			if err != nil {
				return err
			}
			in[i], sizes[i] = x, int(v.Size)
		}
		old, err := m.Get(*op.Out)
		if err != nil {
			return err
		}
		out, err := f(in, sizes, old, int(op.Out.Size))
		if err != nil {
			return err
		}
		return m.Set(*op.Out, out)
	case ir.OpCopy:
		b, err := m.value(op.In[0])
		if err != nil {
			return err
		}
		return m.WriteBytes(op.Out.Space, op.Out.Offset, b)
	}
	if op.Out == nil {
		return fmt.Errorf("%s without output: %w", op.Code, ErrUnsupported)
	}
	wide := op.Out.Size > 8
	for _, v := range op.In {
		wide = wide || v.Size > 8
	}
	if wide {
		return m.execWide(op)
	}
	in := make([]uint64, len(op.In))
	sizes := make([]int, len(op.In))
	for i, v := range op.In {
		x, err := m.Get(v)
		if err != nil {
			return err
		}
		in[i], sizes[i] = x, int(v.Size)
	}
	out, err := ir.Eval(op.Code, int(op.Out.Size), in, sizes)
	if errors.Is(err, ir.ErrNoEval) {
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	if err != nil {
		return err
	}
	return m.Set(*op.Out, out)
}

// value returns the bytes of a varnode of any size, as memory holds them.
func (m *Machine) value(v ir.Varnode) ([]byte, error) {
	if v.Space != ir.SpaceConst {
		return m.ReadBytes(v.Space, v.Offset, int(v.Size))
	}
	// Constants wider than 8 bytes hold their value zero-extended.
	b := make([]byte, v.Size)
	for i := range b {
		shift := 8 * i
		if m.Arch.BigEndian {
			shift = 8 * (len(b) - 1 - i)
		}
		if shift < 64 {
			b[i] = byte(v.Offset >> shift)
		}
	}
	return b, nil
}

// execWide runs an integer op on values wider than 8 bytes.
func (m *Machine) execWide(op ir.Op) error {
	in := make([]*big.Int, len(op.In))
	sizes := make([]int, len(op.In))
	for i, v := range op.In {
		b, err := m.value(v)
		if err != nil {
			return err
		}
		in[i], sizes[i] = m.toBig(b), int(v.Size)
	}
	out, err := ir.EvalWide(op.Code, int(op.Out.Size), in, sizes)
	if errors.Is(err, ir.ErrNoEval) {
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	if err != nil {
		return err
	}
	return m.WriteBytes(op.Out.Space, op.Out.Offset, m.fromBig(out, int(op.Out.Size)))
}

func (m *Machine) toBig(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		if m.Arch.BigEndian {
			be[i] = b[i]
		} else {
			be[i] = b[len(b)-1-i]
		}
	}
	return new(big.Int).SetBytes(be)
}

func (m *Machine) fromBig(v *big.Int, size int) []byte {
	be := v.FillBytes(make([]byte, size))
	if m.Arch.BigEndian {
		return be
	}
	le := make([]byte, size)
	for i := range be {
		le[i] = be[size-1-i]
	}
	return le
}
