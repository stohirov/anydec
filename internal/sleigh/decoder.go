package sleigh

import (
	"errors"
	"fmt"
	"strings"
)

// Memory supplies the bytes being decoded. Read returns up to n bytes at
// addr, fewer at the end of mapped memory, and an error if addr is unmapped.
type Memory interface {
	Read(addr uint64, n int) ([]byte, error)
}

// ErrBadInstruction reports bytes that do not decode under the spec.
var ErrBadInstruction = errors.New("invalid instruction")

// Instruction is one decoded machine instruction.
type Instruction struct {
	Addr     uint64
	Length   int
	Bytes    []byte
	Mnemonic string
	Operands string
	// DelaySlot is the number of bytes of following instructions that
	// execute before this one takes effect (MIPS, SPARC). Decode reports
	// the minimum the spec declares (delayslot(1) is 1); Translate reports
	// the length of the delay-slot instructions it folded into the p-code.
	DelaySlot int
}

func (in *Instruction) String() string {
	if in.Operands == "" {
		return in.Mnemonic
	}
	return in.Mnemonic + " " + in.Operands
}

// Decoder decodes instructions from memory with one spec, tracking the
// context register (such as ARM's TMode) across addresses.
type Decoder struct {
	spec *Spec
	mem  Memory
	ctx  *contextDB
}

// NewDecoder returns a decoder over mem with every context variable zero.
func NewDecoder(spec *Spec, mem Memory) *Decoder {
	return &Decoder{spec: spec, mem: mem, ctx: newContextDB(max(spec.ctxWords, 1))}
}

// Spec returns the decoder's spec.
func (d *Decoder) Spec() *Spec { return d.spec }

func (d *Decoder) contextVar(name string) (*ContextVar, error) {
	v := d.spec.ContextVar(name)
	if v == nil {
		return nil, fmt.Errorf("sleigh: no context variable %q", name)
	}
	return v, nil
}

// SetContextDefault sets a context variable's value wherever no region
// overrides it, as a .pspec <context_set> does. Call it before SetContext.
func (d *Decoder) SetContextDefault(name string, val uint32) error {
	v, err := d.contextVar(name)
	if err != nil {
		return err
	}
	w := &d.ctx.defaults[v.wordIndex]
	*w = *w&^v.mask | val<<v.shift&v.mask
	return nil
}

// SetContext sets a context variable for addresses in [start, end); end 0
// means through the end of the address space. Changes made later by
// decoded instructions (globalset) still flow from their own addresses.
func (d *Decoder) SetContext(name string, start, end uint64, val uint32) error {
	v, err := d.contextVar(name)
	if err != nil {
		return err
	}
	d.ctx.setRegion(start, end, v.wordIndex, v.mask, val<<v.shift&v.mask)
	return nil
}

// Decode decodes the instruction at addr and applies any context changes it
// makes to later addresses.
func (d *Decoder) Decode(addr uint64) (*Instruction, error) {
	in, _, err := d.decode(addr)
	return in, err
}

// decode resolves, prints and applies context for the instruction at addr,
// returning its parse with handles resolved.
func (d *Decoder) decode(addr uint64) (*Instruction, *parserContext, error) {
	c, err := d.resolve(addr)
	if err != nil {
		return nil, nil, err
	}
	in := &Instruction{
		Addr:      addr,
		Length:    c.base.length,
		Bytes:     append([]byte(nil), c.buf[:c.base.length]...),
		DelaySlot: c.delaySlot,
	}
	err = catch(func() {
		w := &walker{ctx: c}
		w.baseState()
		var b strings.Builder
		c.base.ct.printMnemonic(&b, w)
		in.Mnemonic = b.String()
		b.Reset()
		w.baseState()
		c.base.ct.printBody(&b, w)
		in.Operands = b.String()

		c.resolveHandles()
		d.applyCommits(c)
	})
	if err != nil {
		return nil, nil, err
	}
	return in, c, nil
}

// resolve loads bytes and context at addr and matches its constructors.
func (d *Decoder) resolve(addr uint64) (*parserContext, error) {
	if a := uint64(d.spec.Alignment); a > 1 && addr%a != 0 {
		return nil, fmt.Errorf("%w: %#x is not %d-byte aligned", ErrBadInstruction, addr, a)
	}
	b, err := d.mem.Read(addr, maxInsnLen)
	if err != nil {
		return nil, err
	}
	c := &parserContext{spec: d.spec, dec: d, addr: addr, context: make([]uint32, d.ctx.words)}
	copy(c.buf[:], b)
	d.ctx.get(addr, c.context)
	if err := catch(c.resolve); err != nil {
		return nil, err
	}
	if c.base.length <= 0 {
		return nil, fmt.Errorf("%w: %#x: zero-length instruction", ErrBadInstruction, addr)
	}
	if c.base.length > len(b) {
		return nil, fmt.Errorf("%w: %#x: instruction runs past the end of memory", ErrBadInstruction, addr)
	}
	return c, nil
}

// applyCommits carries globalset context changes to the addresses they
// name, as ParserContext::applyCommits does.
func (d *Decoder) applyCommits(c *parserContext) {
	if len(c.commits) == 0 {
		return
	}
	w := &walker{ctx: c}
	w.baseState()
	for _, set := range c.commits {
		var h handle
		if op, ok := set.sym.(*operandSym); ok {
			h = set.point.resolve[op.hand].hand
		} else {
			set.sym.fixedHandle(&h, w)
		}
		addr := h.offsetOffset
		if h.space != nil && h.space.Kind == SpaceConstant {
			addr *= uint64(d.spec.DefaultSpace.WordSize)
		}
		if set.flow {
			d.ctx.setChangePoint(addr, set.num, set.mask, set.value)
		} else {
			d.ctx.setRegion(addr, addr+1, set.num, set.mask, set.value)
		}
	}
}

// catch runs f and converts a badDataError or unimplemented panic into an
// error.
func catch(f func()) (err error) {
	defer func() {
		switch r := recover().(type) {
		case nil:
		case badDataError:
			err = fmt.Errorf("%w: %s", ErrBadInstruction, r.msg)
		case unimplemented:
			err = ErrUnimplemented
		default:
			panic(r)
		}
	}()
	f()
	return nil
}
