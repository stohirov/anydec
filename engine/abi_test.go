package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/irexec"
)

// Calling conventions for the IR interpreter test: how a caller passes the
// vector arguments, where results come back, and how hooks standing in for
// external functions read their arguments.

// callConv marshals one call. Types are the letters of vector signatures.
type callConv interface {
	// arg passes the next argument.
	arg(typ byte, x uint64) error
	// enter sets the stack pointer and return address for the call.
	enter(sp uint64)
	// ret reads the result.
	ret(typ byte) uint64
	// intArg reads integer argument i inside a hook.
	intArg(i int) uint64
	// setRet sets an integer result inside a hook.
	setRet(x uint64)
	// leave does what a hook's return instruction would (x86 pops the
	// return address).
	leave()
}

func newCallConv(a *Analysis, m *irexec.Machine, dir string) (callConv, error) {
	r := regs{a: a, m: m}
	proc, _, _ := strings.Cut(a.Program.Language, ":")
	switch proc {
	case "ARM":
		return &aapcs{regs: r, vfp: dir == "thumb-hf"}, nil
	case "AARCH64":
		return &aapcs64{regs: r}, nil
	case "x86":
		if a.Arch.PointerSize == 8 {
			return &sysv{regs: r}, nil
		}
	}
	return nil, fmt.Errorf("no calling convention for %s: %w", a.Program.Language, irexec.ErrUnsupported)
}

type regs struct {
	a     *Analysis
	m     *irexec.Machine
	stack []uint64 // stack arguments, one slot each
}

func (r *regs) reg(name string) ir.Varnode {
	v, ok := r.a.Register(name)
	if !ok {
		panic("no register " + name)
	}
	return v
}

func (r *regs) set(name string, x uint64) {
	if err := r.m.Set(r.reg(name), x); err != nil {
		panic(err)
	}
}

func (r *regs) get(name string) uint64 {
	x, err := r.m.Get(r.reg(name))
	if err != nil {
		panic(err)
	}
	return x
}

func (r *regs) load(addr uint64, size int) uint64 {
	x, err := r.m.Load(ir.SpaceRAM, addr, size)
	if err != nil {
		panic(err)
	}
	return x
}

func (r *regs) push(sp uint64, slot int) {
	for i, w := range r.stack {
		if err := r.m.Store(ir.SpaceRAM, sp+uint64(slot*i), slot, w); err != nil {
			panic(err)
		}
	}
}

// extend widens a narrow integer as callers do.
func extend(typ byte, x uint64) uint64 {
	switch typ {
	case 'c':
		return uint64(int64(int8(x)))
	case 's':
		return uint64(int64(int16(x)))
	case 'C':
		return x & 0xff
	case 'S':
		return x & 0xffff
	case 'i':
		return uint64(int64(int32(x)))
	}
	return x
}

// narrow masks a result to its type.
func narrow(typ byte, x uint64) uint64 {
	switch typ {
	case 'I', 'U', 'd', 'p':
		return x
	case 's', 'S':
		return x & 0xffff
	case 'c', 'C':
		return x & 0xff
	}
	return x & 0xffffffff
}

// aapcs passes arguments the 32-bit ARM way: integers in r0-r3 then the
// stack, 64-bit values in even register pairs; with vfp, floats and
// doubles in s0-s15 and d0-d7 with back-filling.
type aapcs struct {
	regs
	vfp   bool
	ncrn  int
	sregs [16]bool
}

func (c *aapcs) word(x uint64) {
	if c.ncrn < 4 {
		c.set(fmt.Sprintf("r%d", c.ncrn), x&0xffffffff)
		c.ncrn++
		return
	}
	c.stack = append(c.stack, x&0xffffffff)
}

func (c *aapcs) dword(x uint64) {
	c.ncrn = (c.ncrn + 1) &^ 1
	if c.ncrn < 4 {
		c.word(x)
		c.word(x >> 32)
		return
	}
	c.ncrn = 4
	if len(c.stack)%2 != 0 {
		c.stack = append(c.stack, 0)
	}
	c.stack = append(c.stack, x&0xffffffff, x>>32)
}

func (c *aapcs) arg(typ byte, x uint64) error {
	switch {
	case typ == 'f' && c.vfp:
		for i := range c.sregs {
			if !c.sregs[i] {
				c.sregs[i] = true
				c.set(fmt.Sprintf("s%d", i), x)
				return nil
			}
		}
		return errors.New("out of VFP registers")
	case typ == 'd' && c.vfp:
		for i := 0; i < 16; i += 2 {
			if !c.sregs[i] && !c.sregs[i+1] {
				c.sregs[i], c.sregs[i+1] = true, true
				c.set(fmt.Sprintf("d%d", i/2), x)
				return nil
			}
		}
		return errors.New("out of VFP registers")
	case typ == 'd' || typ == 'I' || typ == 'U':
		c.dword(x)
	default:
		c.word(extend(typ, x))
	}
	return nil
}

func (c *aapcs) enter(sp uint64) {
	c.push(sp, 4)
	c.set("sp", sp)
	c.set("lr", 0xdead0000)
}

func (c *aapcs) ret(typ byte) uint64 {
	switch {
	case typ == 'f' && c.vfp:
		return c.get("s0")
	case typ == 'd' && c.vfp:
		return c.get("d0")
	case typ == 'd' || typ == 'I' || typ == 'U':
		return c.get("r0") | c.get("r1")<<32
	}
	return narrow(typ, c.get("r0"))
}

func (c *aapcs) intArg(i int) uint64 {
	if i < 4 {
		return c.get(fmt.Sprintf("r%d", i))
	}
	return c.load(c.get("sp")+uint64(4*(i-4)), 4)
}

func (c *aapcs) setRet(x uint64) { c.set("r0", x&0xffffffff) }
func (c *aapcs) leave()          {}

// aapcs64 passes integers in x0-x7 and floats in v0-v7, then the stack.
type aapcs64 struct {
	regs
	ngrn, nsrn int
}

func (c *aapcs64) arg(typ byte, x uint64) error {
	switch typ {
	case 'f', 'd':
		if c.nsrn >= 8 {
			return errors.New("float arguments on the stack are not modeled")
		}
		name := "s"
		if typ == 'd' {
			name = "d"
		}
		c.set(fmt.Sprintf("%s%d", name, c.nsrn), x)
		c.nsrn++
	default:
		if c.ngrn < 8 {
			c.set(fmt.Sprintf("x%d", c.ngrn), extend(typ, x))
			c.ngrn++
		} else {
			c.stack = append(c.stack, extend(typ, x))
		}
	}
	return nil
}

func (c *aapcs64) enter(sp uint64) {
	c.push(sp, 8)
	c.set("sp", sp)
	c.set("x30", 0xdead0000)
}

func (c *aapcs64) ret(typ byte) uint64 {
	switch typ {
	case 'f':
		return c.get("s0")
	case 'd':
		return c.get("d0")
	}
	return narrow(typ, c.get("x0"))
}

func (c *aapcs64) intArg(i int) uint64 {
	if i < 8 {
		return c.get(fmt.Sprintf("x%d", i))
	}
	return c.load(c.get("sp")+uint64(8*(i-8)), 8)
}

func (c *aapcs64) setRet(x uint64) { c.set("x0", x) }
func (c *aapcs64) leave()          {}

// sysv is the System V x86-64 convention: integers in RDI, RSI, RDX, RCX,
// R8, R9, floats in XMM0-7, then the stack above the return address.
type sysv struct {
	regs
	ngrn, nsrn int
}

var sysvInts = []string{"RDI", "RSI", "RDX", "RCX", "R8", "R9"}

func (c *sysv) arg(typ byte, x uint64) error {
	switch typ {
	case 'f', 'd':
		if c.nsrn >= 8 {
			return errors.New("float arguments on the stack are not modeled")
		}
		part := "Da"
		if typ == 'd' {
			part = "Qa"
		}
		c.set(fmt.Sprintf("XMM%d_%s", c.nsrn, part), x)
		c.nsrn++
	default:
		if c.ngrn < len(sysvInts) {
			c.set(sysvInts[c.ngrn], extend(typ, x))
			c.ngrn++
		} else {
			c.stack = append(c.stack, extend(typ, x))
		}
	}
	return nil
}

func (c *sysv) enter(sp uint64) {
	// At entry RSP+8 is 16-byte aligned and [RSP] is the return address.
	sp -= 8
	c.push(sp+8, 8)
	if err := c.m.Store(ir.SpaceRAM, sp, 8, 0xdead0000); err != nil {
		panic(err)
	}
	c.set("RSP", sp)
	c.set("RAX", uint64(c.nsrn)) // AL: vector registers used, for varargs
}

func (c *sysv) ret(typ byte) uint64 {
	switch typ {
	case 'f':
		return c.get("XMM0_Da")
	case 'd':
		return c.get("XMM0_Qa")
	}
	return narrow(typ, c.get("RAX"))
}

func (c *sysv) intArg(i int) uint64 {
	if i < len(sysvInts) {
		return c.get(sysvInts[i])
	}
	return c.load(c.get("RSP")+8+uint64(8*(i-len(sysvInts))), 8)
}

func (c *sysv) setRet(x uint64) { c.set("RAX", x) }
func (c *sysv) leave()          { c.set("RSP", c.get("RSP")+8) }
