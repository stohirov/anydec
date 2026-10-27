// Package loader turns executable artifacts into a Program: segments with
// addresses and permissions, entry points, symbols, relocations and imports.
// Formats: ELF (32/64, LE/BE), PE/COFF, Mach-O, and raw images whose ISA,
// endianness and base address come from the user or the baremetal package.
package loader

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

// ErrUnsupportedFormat is returned for inputs no loader recognizes.
var ErrUnsupportedFormat = errors.New("unsupported executable format")

// Perm is a set of memory permissions.
type Perm uint8

const (
	PermR Perm = 1 << iota
	PermW
	PermX
)

func (p Perm) String() string {
	b := []byte("---")
	if p&PermR != 0 {
		b[0] = 'r'
	}
	if p&PermW != 0 {
		b[1] = 'w'
	}
	if p&PermX != 0 {
		b[2] = 'x'
	}
	return string(b)
}

// Segment is a contiguous run of loaded memory. Data holds the full in-memory
// image, zero-filled past what the file supplied (as for .bss).
type Segment struct {
	Name string
	Addr uint64
	Data []byte
	Perm Perm
}

// End returns the first address past the segment.
func (s *Segment) End() uint64 { return s.Addr + uint64(len(s.Data)) }

// SymbolKind says what a symbol names.
type SymbolKind string

const (
	SymFunction SymbolKind = "function"
	SymObject   SymbolKind = "object"
	SymImport   SymbolKind = "import"
)

// Symbol is a named address taken from the input file.
type Symbol struct {
	Name string
	Addr uint64
	Size uint64
	Kind SymbolKind
}

// Mode is the instruction-set mode of a code region, for ISAs that switch
// between encodings at run time (ARM and Thumb).
type Mode uint8

const (
	ModeDefault Mode = iota // the ISA's primary encoding (ARM on ARM)
	ModeThumb
	ModeData // literal pools and other data inside code sections
)

func (m Mode) String() string {
	switch m {
	case ModeDefault:
		return "default"
	case ModeThumb:
		return "thumb"
	case ModeData:
		return "data"
	}
	return fmt.Sprintf("mode(%d)", uint8(m))
}

// ModeRange starts a region in Mode at Addr; it holds until the next range.
type ModeRange struct {
	Addr uint64
	Mode Mode
}

// Relocation is a place the linker or dynamic loader patches. The loader
// records relocations but does not apply them, so bytes at Addr are as the
// file stores them.
type Relocation struct {
	Addr   uint64
	Type   uint32 // ELF r_type for the file's machine
	Symbol string // target symbol, or "" for section-relative relocations
	Addend int64
}

// Program is a loaded executable, ready for decoding and analysis.
type Program struct {
	Format string // "elf"
	// Language is the SLEIGH language id the code is decoded with, such as
	// "ARM:LE:32:v8". Empty when the loader cannot tell.
	Language  string
	BigEndian bool
	Entry     uint64
	Segments  []Segment    // sorted by address, non-overlapping
	Symbols   []Symbol     // sorted by address, then name
	Modes     []ModeRange  // sorted by address; empty means ModeDefault throughout
	Relocs    []Relocation // sorted by address
}

// Load parses data as an executable in any supported format.
func Load(data []byte) (*Program, error) {
	if bytes.HasPrefix(data, []byte("\x7fELF")) {
		return loadELF(data)
	}
	return nil, ErrUnsupportedFormat
}

// Segment returns the segment containing addr, or nil.
func (p *Program) Segment(addr uint64) *Segment {
	i := sort.Search(len(p.Segments), func(i int) bool { return p.Segments[i].End() > addr })
	if i < len(p.Segments) && p.Segments[i].Addr <= addr {
		return &p.Segments[i]
	}
	return nil
}

// Read returns up to n bytes starting at addr, stopping at the end of the
// containing segment. It fails if addr is not mapped.
func (p *Program) Read(addr uint64, n int) ([]byte, error) {
	s := p.Segment(addr)
	if s == nil {
		return nil, fmt.Errorf("address %#x is not mapped", addr)
	}
	off := addr - s.Addr
	end := min(off+uint64(n), uint64(len(s.Data)))
	return s.Data[off:end], nil
}

// ModeAt returns the instruction-set mode in effect at addr.
func (p *Program) ModeAt(addr uint64) Mode {
	i := sort.Search(len(p.Modes), func(i int) bool { return p.Modes[i].Addr > addr })
	if i == 0 {
		return ModeDefault
	}
	return p.Modes[i-1].Mode
}

// RelocsIn returns the relocations whose address is in [start, end).
func (p *Program) RelocsIn(start, end uint64) []Relocation {
	i := sort.Search(len(p.Relocs), func(i int) bool { return p.Relocs[i].Addr >= start })
	j := i
	for j < len(p.Relocs) && p.Relocs[j].Addr < end {
		j++
	}
	return p.Relocs[i:j]
}

// Symbol returns the function or object symbol at exactly addr, if any.
func (p *Program) Symbol(addr uint64) (Symbol, bool) {
	i := sort.Search(len(p.Symbols), func(i int) bool { return p.Symbols[i].Addr >= addr })
	for ; i < len(p.Symbols) && p.Symbols[i].Addr == addr; i++ {
		if p.Symbols[i].Kind != SymImport {
			return p.Symbols[i], true
		}
	}
	return Symbol{}, false
}

// Lookup returns the first function or object symbol with the given name.
func (p *Program) Lookup(name string) (Symbol, bool) {
	for _, s := range p.Symbols {
		if s.Name == name && s.Kind != SymImport {
			return s, true
		}
	}
	return Symbol{}, false
}
