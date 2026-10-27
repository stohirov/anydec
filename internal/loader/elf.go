package loader

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// maxImage caps the memory a single input may ask the loader to allocate, so
// a crafted header cannot exhaust memory.
const maxImage = 1 << 30

func loadELF(data []byte, relocate bool) (*Program, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("elf: %w", err)
	}
	p := &Program{
		Format:    "elf",
		Language:  elfLanguage(f),
		BigEndian: f.Data == elf.ELFDATA2MSB,
		Entry:     f.Entry,
		HasEntry:  f.Type != elf.ET_REL && f.Entry != 0,
	}

	// Executables and shared objects say where to map memory in program
	// headers. Relocatable objects (.o files) only have sections at address
	// zero, so lay their allocated sections out one after another.
	var sectionAddr []uint64
	var externs map[string]uint64
	if f.Type == elf.ET_REL {
		if sectionAddr, err = p.layoutSections(f); err == nil {
			externs, err = p.placeExterns(f)
		}
	} else {
		err = p.mapProgramHeaders(f, data)
	}
	if err != nil {
		return nil, fmt.Errorf("elf: %w", err)
	}
	sort.Slice(p.Segments, func(i, j int) bool { return p.Segments[i].Addr < p.Segments[j].Addr })
	for i := 1; i < len(p.Segments); i++ {
		if p.Segments[i].Addr < p.Segments[i-1].End() {
			return nil, fmt.Errorf("elf: segments %s and %s overlap", p.Segments[i-1].Name, p.Segments[i].Name)
		}
	}

	if err := p.readSymbols(f, sectionAddr, externs); err != nil {
		return nil, fmt.Errorf("elf: %w", err)
	}
	if err := p.readRelocs(f, sectionAddr, externs, relocate && f.Type == elf.ET_REL); err != nil {
		return nil, fmt.Errorf("elf: %w", err)
	}
	return p, nil
}

// placeExterns gives each undefined symbol of a relocatable object a
// pointer-sized slot in a new segment past the loaded sections.
func (p *Program) placeExterns(f *elf.File) (map[string]uint64, error) {
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	slot := uint64(4)
	if f.Class == elf.ELFCLASS64 {
		slot = 8
	}
	next := uint64(0)
	for _, s := range p.Segments {
		next = max(next, s.End())
	}
	base := (next + 15) &^ 15
	externs := map[string]uint64{}
	for _, s := range syms {
		if s.Section != elf.SHN_UNDEF || s.Name == "" {
			continue
		}
		if _, dup := externs[s.Name]; !dup {
			externs[s.Name] = base + slot*uint64(len(externs))
		}
	}
	if len(externs) > 0 {
		p.Segments = append(p.Segments, Segment{
			Name: ExternalSegment,
			Addr: base,
			Data: make([]byte, slot*uint64(len(externs))),
			Perm: PermR,
		})
	}
	return externs, nil
}

// readRelocs records the REL and RELA entries that patch allocated
// sections, and applies them when relocate is set.
func (p *Program) readRelocs(f *elf.File, sectionAddr []uint64, externs map[string]uint64, relocate bool) error {
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return err
	}
	dyn, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return err
	}
	is64 := f.Class == elf.ELFCLASS64
	for _, s := range f.Sections {
		if s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA {
			continue
		}
		var base uint64
		if sectionAddr != nil {
			// In an object, offsets are relative to the patched section.
			if int(s.Info) >= len(f.Sections) || f.Sections[s.Info].Flags&elf.SHF_ALLOC == 0 {
				continue
			}
			base = sectionAddr[s.Info]
		}
		table := syms
		if int(s.Link) < len(f.Sections) && f.Sections[s.Link].Type == elf.SHT_DYNSYM {
			table = dyn
		}
		data, err := s.Data()
		if err != nil {
			return fmt.Errorf("section %s: %w", s.Name, err)
		}
		size := map[[2]bool]int{{false, false}: 8, {false, true}: 12, {true, false}: 16, {true, true}: 24}[[2]bool{is64, s.Type == elf.SHT_RELA}]
		bo := f.ByteOrder
		for off := 0; off+size <= len(data); off += size {
			e := data[off : off+size]
			var r Relocation
			var symIdx uint32
			if is64 {
				info := bo.Uint64(e[8:])
				r.Addr, symIdx, r.Type = bo.Uint64(e), uint32(info>>32), uint32(info)
				if size == 24 {
					r.Addend = int64(bo.Uint64(e[16:]))
				}
			} else {
				info := bo.Uint32(e[4:])
				r.Addr, symIdx, r.Type = uint64(bo.Uint32(e)), info>>8, info&0xff
				if size == 12 {
					r.Addend = int64(int32(bo.Uint32(e[8:])))
				}
			}
			r.Addr += base
			var target relocTarget
			if symIdx > 0 && int(symIdx) <= len(table) {
				sym := table[symIdx-1]
				r.Symbol = sym.Name
				target = resolveSymbol(f, sym, sectionAddr, externs)
			}
			if relocate && target.ok {
				r.Applied = p.applyReloc(f, r, target)
			}
			p.Relocs = append(p.Relocs, r)
		}
	}
	sort.SliceStable(p.Relocs, func(i, j int) bool { return p.Relocs[i].Addr < p.Relocs[j].Addr })
	return nil
}

func (p *Program) mapProgramHeaders(f *elf.File, data []byte) error {
	total := uint64(0)
	for _, ph := range f.Progs {
		if ph.Type != elf.PT_LOAD || ph.Memsz == 0 {
			continue
		}
		if ph.Filesz > ph.Memsz || ph.Off > uint64(len(data)) || ph.Filesz > uint64(len(data))-ph.Off {
			return fmt.Errorf("load segment at %#x has a bad file range", ph.Vaddr)
		}
		if total += ph.Memsz; total > maxImage {
			return errors.New("load segments are too large")
		}
		mem := make([]byte, ph.Memsz)
		copy(mem, data[ph.Off:ph.Off+ph.Filesz])
		var perm Perm
		if ph.Flags&elf.PF_R != 0 {
			perm |= PermR
		}
		if ph.Flags&elf.PF_W != 0 {
			perm |= PermW
		}
		if ph.Flags&elf.PF_X != 0 {
			perm |= PermX
		}
		p.Segments = append(p.Segments, Segment{
			Name: fmt.Sprintf("LOAD%d", len(p.Segments)),
			Addr: ph.Vaddr,
			Data: mem,
			Perm: perm,
		})
	}
	return nil
}

// layoutSections places each allocated section of a relocatable object at
// increasing aligned addresses from zero, and returns every section's
// address, indexed like f.Sections.
func (p *Program) layoutSections(f *elf.File) ([]uint64, error) {
	addrs := make([]uint64, len(f.Sections))
	next := uint64(0)
	for i, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC == 0 || s.Size == 0 {
			continue
		}
		if s.Size > maxImage || next+s.Size > maxImage {
			return nil, errors.New("sections are too large")
		}
		if a := s.Addralign; a > 1 && a <= maxImage {
			next = (next + a - 1) / a * a
		}
		mem := make([]byte, s.Size)
		if s.Type != elf.SHT_NOBITS {
			b, err := s.Data()
			if err != nil {
				return nil, fmt.Errorf("section %s: %w", s.Name, err)
			}
			copy(mem, b)
		}
		perm := PermR
		if s.Flags&elf.SHF_WRITE != 0 {
			perm |= PermW
		}
		if s.Flags&elf.SHF_EXECINSTR != 0 {
			perm |= PermX
		}
		addrs[i] = next
		p.Segments = append(p.Segments, Segment{Name: s.Name, Addr: next, Data: mem, Perm: perm})
		next += s.Size
	}
	return addrs, nil
}

func (p *Program) readSymbols(f *elf.File, sectionAddr []uint64, externs map[string]uint64) error {
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return err
	}
	dyn, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return err
	}

	arm := f.Machine == elf.EM_ARM
	mapped := map[uint64]bool{} // addresses with an explicit mapping symbol
	var funcModes []ModeRange
	seen := map[Symbol]bool{}

	for _, s := range append(syms, dyn...) {
		typ := elf.ST_TYPE(s.Info)
		if typ == elf.STT_SECTION || typ == elf.STT_FILE || s.Name == "" {
			continue
		}
		addr := s.Value
		if sectionAddr != nil && s.Section < elf.SHN_LORESERVE && int(s.Section) < len(sectionAddr) {
			addr += sectionAddr[s.Section]
		}
		if m, ok := mappingSymbol(f.Machine, s.Name); ok {
			// Only mapping symbols in loaded sections mark code; LLVM also
			// puts a $d in .comment, which is not mapped.
			if s.Section != elf.SHN_UNDEF && int(s.Section) < len(f.Sections) && f.Sections[s.Section].Flags&elf.SHF_ALLOC != 0 {
				p.Modes = append(p.Modes, ModeRange{addr, m})
				mapped[addr] = true
			}
			continue
		}

		sym := Symbol{Name: s.Name, Addr: addr, Size: s.Size}
		switch {
		case s.Section == elf.SHN_UNDEF:
			sym.Kind, sym.Addr = SymImport, externs[s.Name]
		case s.Section == elf.SHN_COMMON:
			continue
		case typ == elf.STT_FUNC:
			sym.Kind = SymFunction
			if arm && addr&1 != 0 {
				sym.Addr = addr &^ 1
				funcModes = append(funcModes, ModeRange{sym.Addr, ModeThumb})
			}
		case typ == elf.STT_OBJECT || typ == elf.STT_TLS:
			sym.Kind = SymObject
		case typ == elf.STT_NOTYPE && p.executable(sym.Addr):
			sym.Kind = SymFunction
		default:
			sym.Kind = SymObject
		}
		if !seen[sym] {
			seen[sym] = true
			p.Symbols = append(p.Symbols, sym)
		}
	}

	if arm && p.Entry&1 != 0 {
		p.Entry &^= 1
		funcModes = append(funcModes, ModeRange{p.Entry, ModeThumb})
	}
	for _, m := range funcModes {
		if !mapped[m.Addr] {
			p.Modes = append(p.Modes, m)
			mapped[m.Addr] = true
		}
	}

	sort.Slice(p.Symbols, func(i, j int) bool {
		a, b := p.Symbols[i], p.Symbols[j]
		if a.Addr != b.Addr {
			return a.Addr < b.Addr
		}
		return a.Name < b.Name
	})
	sort.SliceStable(p.Modes, func(i, j int) bool { return p.Modes[i].Addr < p.Modes[j].Addr })
	return nil
}

func (p *Program) executable(addr uint64) bool {
	s := p.Segment(addr)
	return s != nil && s.Perm&PermX != 0
}

// mappingSymbol decodes the ARM ELF ABI mapping symbols ($a, $t, $d, and
// $x on AArch64, optionally followed by ".suffix") that mark where code in
// each instruction set and embedded data begin.
func mappingSymbol(m elf.Machine, name string) (Mode, bool) {
	if m != elf.EM_ARM && m != elf.EM_AARCH64 {
		return 0, false
	}
	if len(name) < 2 || name[0] != '$' || (len(name) > 2 && !strings.HasPrefix(name[2:], ".")) {
		return 0, false
	}
	switch name[1] {
	case 'a', 'x':
		return ModeDefault, true
	case 't':
		return ModeThumb, m == elf.EM_ARM
	case 'd':
		return ModeData, true
	}
	return 0, false
}

// elfLanguage maps an ELF machine to the SLEIGH language id that decodes it.
func elfLanguage(f *elf.File) string {
	endian := "LE"
	if f.Data == elf.ELFDATA2MSB {
		endian = "BE"
	}
	is64 := f.Class == elf.ELFCLASS64
	switch f.Machine {
	case elf.EM_ARM:
		return "ARM:" + endian + ":32:v8"
	case elf.EM_AARCH64:
		return "AARCH64:" + endian + ":64:v8A"
	case elf.EM_MIPS:
		if is64 {
			return "MIPS:" + endian + ":64:default"
		}
		return "MIPS:" + endian + ":32:default"
	case elf.EM_386:
		return "x86:LE:32:default"
	case elf.EM_X86_64:
		return "x86:LE:64:default"
	case elf.EM_PPC:
		return "PowerPC:" + endian + ":32:default"
	case elf.EM_PPC64:
		return "PowerPC:" + endian + ":64:default"
	case elf.EM_RISCV:
		if is64 {
			return "RISCV:LE:64:RV64GC"
		}
		return "RISCV:LE:32:RV32GC"
	}
	return ""
}
