package engine

import (
	"errors"
	"fmt"
	"sync"

	"github.com/stohirov/decompile-anything/internal/loader"
	"github.com/stohirov/decompile-anything/internal/sleigh"
	"github.com/stohirov/decompile-anything/third_party/ghidra"
)

// Program is a loaded executable.
type Program = loader.Program

// Load parses an executable (ELF today) into a Program.
func Load(data []byte) (*Program, error) {
	return loader.Load(data)
}

// Line is one line of a disassembly listing: an instruction, or bytes that
// are data or do not decode.
type Line struct {
	Addr  uint64
	Bytes []byte
	// Insn is nil for data and for bytes that do not decode; Err says why
	// in the second case.
	Insn *sleigh.Instruction
	Err  error
}

// Text returns the instruction text, or a data directive.
func (l Line) Text() string {
	if l.Insn != nil {
		return l.Insn.String()
	}
	if l.Err != nil {
		return "(bad)"
	}
	return ".data"
}

var languages sync.Map // language id -> *sleigh.Language

func language(id string) (*sleigh.Language, error) {
	if l, ok := languages.Load(id); ok {
		return l.(*sleigh.Language), nil
	}
	l, err := sleigh.LoadLanguage(ghidra.Processors, id)
	if err != nil {
		return nil, err
	}
	languages.Store(id, l)
	return l, nil
}

// Disassembler decodes a Program's code.
type Disassembler struct {
	prog *Program
	dec  *sleigh.Decoder
}

// NewDisassembler prepares to decode p with the SLEIGH spec for its
// language, honoring the instruction-set modes the loader found.
func NewDisassembler(p *Program) (*Disassembler, error) {
	if p.Language == "" {
		return nil, errors.New("unknown processor; no SLEIGH language for this binary")
	}
	lang, err := language(p.Language)
	if err != nil {
		return nil, err
	}
	dec := lang.NewDecoder(p)
	if err := applyModes(dec, p); err != nil {
		return nil, err
	}
	return &Disassembler{prog: p, dec: dec}, nil
}

// applyModes sets the context variables that select an instruction set in
// each region (ARM's TMode for Thumb code).
func applyModes(dec *sleigh.Decoder, p *Program) error {
	if dec.Spec().ContextVar("TMode") == nil {
		return nil
	}
	for i, m := range p.Modes {
		var end uint64
		if i+1 < len(p.Modes) {
			end = p.Modes[i+1].Addr
		}
		var thumb uint32
		if m.Mode == loader.ModeThumb {
			thumb = 1
		}
		if err := dec.SetContext("TMode", m.Addr, end, thumb); err != nil {
			return err
		}
	}
	return nil
}

// Range decodes [start, end) linearly and calls fn for each line. Data
// regions are emitted in 4-byte units; undecodable bytes advance by the
// spec's alignment.
func (d *Disassembler) Range(start, end uint64, fn func(Line)) error {
	align := uint64(max(d.dec.Spec().Alignment, 1))
	for addr := start; addr < end; {
		if d.prog.ModeAt(addr) == loader.ModeData {
			n := min(4, end-addr, d.nextModeChange(addr)-addr)
			b, err := d.prog.Read(addr, int(n))
			if err != nil {
				return err
			}
			fn(Line{Addr: addr, Bytes: b})
			addr += uint64(len(b))
			continue
		}
		in, err := d.dec.Decode(addr)
		if err != nil {
			if !errors.Is(err, sleigh.ErrBadInstruction) {
				return err
			}
			b, rerr := d.prog.Read(addr, int(align))
			if rerr != nil {
				return rerr
			}
			fn(Line{Addr: addr, Bytes: b, Err: err})
			addr += uint64(len(b))
			continue
		}
		fn(Line{Addr: addr, Bytes: in.Bytes, Insn: in})
		addr += uint64(in.Length)
	}
	return nil
}

func (d *Disassembler) nextModeChange(addr uint64) uint64 {
	for _, m := range d.prog.Modes {
		if m.Addr > addr {
			return m.Addr
		}
	}
	return ^uint64(0)
}

// Decode decodes the single instruction at addr.
func (d *Disassembler) Decode(addr uint64) (*sleigh.Instruction, error) {
	in, err := d.dec.Decode(addr)
	if err != nil {
		return nil, fmt.Errorf("decode %#x: %w", addr, err)
	}
	return in, nil
}

// Translate decodes the instruction at addr and returns its raw p-code.
func (d *Disassembler) Translate(addr uint64) (*sleigh.Instruction, []sleigh.PcodeOp, error) {
	in, ops, err := d.dec.Translate(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("translate %#x: %w", addr, err)
	}
	return in, ops, nil
}

// Spec returns the SLEIGH spec the disassembler decodes with.
func (d *Disassembler) Spec() *sleigh.Spec { return d.dec.Spec() }
