package loader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func loadFile(t *testing.T, path string) *Program {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRelocatableARMObject(t *testing.T) {
	p := loadFile(t, filepath.Join("..", "..", "testdata", "synthetic", "arm", "arith-O2.o"))
	if p.Language != "ARM:LE:32:v8" || p.BigEndian {
		t.Errorf("language %q big-endian %v", p.Language, p.BigEndian)
	}
	text := p.Segments[0]
	if text.Name != ".text" || text.Addr != 0 || text.Perm != PermR|PermX {
		t.Errorf("first segment = %s at %#x %s, want .text at 0 r-x", text.Name, text.Addr, text.Perm)
	}
	add, ok := p.Lookup("add")
	if !ok || add.Kind != SymFunction || add.Addr != 0 {
		t.Fatalf("add = %+v, %v", add, ok)
	}
	// add r0, r1, r0; bx lr
	if b, _ := p.Read(add.Addr, 8); !bytes.Equal(b, []byte{0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1}) {
		t.Errorf("add bytes = % x", b)
	}
	if m := p.ModeAt(add.Addr); m != ModeDefault {
		t.Errorf("mode at add = %s, want default", m)
	}
}

func TestThumbObjectModes(t *testing.T) {
	p := loadFile(t, filepath.Join("..", "..", "testdata", "synthetic", "thumb", "arith-O2.o"))
	mul, ok := p.Lookup("mul_add")
	if !ok {
		t.Fatal("mul_add not found")
	}
	if mul.Addr&1 != 0 {
		t.Errorf("thumb bit left in address %#x", mul.Addr)
	}
	if m := p.ModeAt(mul.Addr); m != ModeThumb {
		t.Errorf("mode at mul_add = %s, want thumb", m)
	}
	if s, ok := p.Symbol(mul.Addr); !ok || s.Name != "mul_add" {
		t.Errorf("Symbol(%#x) = %+v, %v", mul.Addr, s, ok)
	}
}

func TestImportsFromObject(t *testing.T) {
	p := loadFile(t, filepath.Join("..", "..", "testdata", "synthetic", "arm", "calls-O0.o"))
	imports := map[string]bool{}
	for _, s := range p.Symbols {
		if s.Kind == SymImport {
			imports[s.Name] = true
		}
	}
	for _, name := range []string{"printf"} {
		if !imports[name] {
			t.Errorf("import %s missing; got %v", name, imports)
		}
	}
	if _, ok := p.Lookup("printf"); ok {
		t.Error("Lookup returned an import")
	}

	report, _ := p.Lookup("report")
	var called bool
	for _, r := range p.RelocsIn(report.Addr, report.Addr+report.Size) {
		if r.Symbol == "printf" {
			called = true
		}
	}
	if !called {
		t.Errorf("no relocation for the call to printf in report; relocs %+v", p.Relocs)
	}
}

// elf32Exec builds a minimal little-endian ARM executable: one PT_LOAD
// segment holding code at vaddr with memsz bytes, and no sections.
func elf32Exec(entry, vaddr uint32, code []byte, memsz uint32) []byte {
	const ehsize, phsize = 52, 32
	var b bytes.Buffer
	le := binary.LittleEndian
	b.Write([]byte{0x7f, 'E', 'L', 'F', 1, 1, 1, 0})
	b.Write(make([]byte, 8))
	binary.Write(&b, le, uint16(2))  // e_type: ET_EXEC
	binary.Write(&b, le, uint16(40)) // e_machine: EM_ARM
	binary.Write(&b, le, uint32(1))  // e_version
	binary.Write(&b, le, entry)
	binary.Write(&b, le, uint32(ehsize)) // e_phoff
	binary.Write(&b, le, uint32(0))      // e_shoff
	binary.Write(&b, le, uint32(0x05000000))
	binary.Write(&b, le, uint16(ehsize))
	binary.Write(&b, le, uint16(phsize))
	binary.Write(&b, le, uint16(1)) // e_phnum
	binary.Write(&b, le, uint16(40))
	binary.Write(&b, le, uint16(0))
	binary.Write(&b, le, uint16(0))

	binary.Write(&b, le, uint32(1)) // PT_LOAD
	binary.Write(&b, le, uint32(ehsize+phsize))
	binary.Write(&b, le, vaddr)
	binary.Write(&b, le, vaddr)
	binary.Write(&b, le, uint32(len(code)))
	binary.Write(&b, le, memsz)
	binary.Write(&b, le, uint32(5)) // PF_R | PF_X
	binary.Write(&b, le, uint32(4))
	b.Write(code)
	return b.Bytes()
}

func TestExecutableProgramHeaders(t *testing.T) {
	code := []byte{0x08, 0x44, 0x70, 0x47} // thumb: add r0, r1; bx lr
	p, err := Load(elf32Exec(0x8001, 0x8000, code, 16))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Segments) != 1 {
		t.Fatalf("got %d segments", len(p.Segments))
	}
	s := p.Segments[0]
	if s.Addr != 0x8000 || len(s.Data) != 16 || s.Perm != PermR|PermX {
		t.Errorf("segment %#x len %d %s", s.Addr, len(s.Data), s.Perm)
	}
	if !bytes.Equal(s.Data[:4], code) || !bytes.Equal(s.Data[4:], make([]byte, 12)) {
		t.Errorf("segment data % x", s.Data)
	}
	if p.Entry != 0x8000 || p.ModeAt(p.Entry) != ModeThumb {
		t.Errorf("entry %#x mode %s, want 0x8000 thumb", p.Entry, p.ModeAt(p.Entry))
	}
	if b, err := p.Read(0x800c, 100); err != nil || len(b) != 4 {
		t.Errorf("read at segment tail: %d bytes, %v", len(b), err)
	}
	if _, err := p.Read(0x9000, 1); err == nil {
		t.Error("read of unmapped address succeeded")
	}
}

func TestRejectsBadInputs(t *testing.T) {
	code := []byte{0, 0, 0, 0}
	huge := elf32Exec(0x8000, 0x8000, code, 0xffffffff)
	truncated := elf32Exec(0x8000, 0x8000, code, 4)
	truncated = truncated[:len(truncated)-2]

	if _, err := Load([]byte("MZ")); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("PE: got %v", err)
	}
	if _, err := Load(huge); err == nil {
		t.Error("4 GiB segment loaded")
	}
	if _, err := Load(truncated); err == nil {
		t.Error("segment past end of file loaded")
	}
}

// callTarget decodes the destination of the ARM BL/BLX or Thumb-2 BL/BLX
// at addr.
func callTarget(t *testing.T, p *Program, addr uint64, thumb bool) uint64 {
	t.Helper()
	b, err := p.Read(addr, 4)
	if err != nil {
		t.Fatal(err)
	}
	if thumb {
		hi, lo := binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:])
		target := addr + 4 + uint64(signExtend(thumbBranchImm(hi, lo), thumbBranchRange))
		if lo&(1<<12) == 0 { // BLX
			target &^= 3
		}
		return target
	}
	w := binary.LittleEndian.Uint32(b)
	off := signExtend(uint64(w&0xffffff)<<2, armBranchRange)
	if w>>28 == armUncond {
		off |= int64(w >> 23 & 2)
	}
	return addr + 8 + uint64(off)
}

func TestAppliesCallRelocations(t *testing.T) {
	for _, tc := range []struct {
		dir   string
		thumb bool
	}{{"arm", false}, {"thumb", true}} {
		p := loadFile(t, filepath.Join("..", "..", "testdata", "synthetic", tc.dir, "calls-O0.o"))
		printf := -1
		for i, s := range p.Symbols {
			if s.Name == "printf" && s.Kind == SymImport {
				printf = i
			}
		}
		if printf < 0 {
			t.Fatalf("%s: no printf import", tc.dir)
		}
		ext := p.Segment(p.Symbols[printf].Addr)
		if ext == nil || ext.Name != ExternalSegment || ext.Perm&PermX != 0 {
			t.Fatalf("%s: printf at %#x is not in a data-only external segment", tc.dir, p.Symbols[printf].Addr)
		}
		if s, ok := p.Import(p.Symbols[printf].Addr); !ok || s.Name != "printf" {
			t.Errorf("%s: Import(%#x) = %+v, %v", tc.dir, p.Symbols[printf].Addr, s, ok)
		}
		calls := 0
		for _, r := range p.Relocs {
			if r.Type != rARMCall && r.Type != rARMThmCall {
				continue
			}
			if !r.Applied {
				t.Errorf("%s: call relocation at %#x to %s not applied", tc.dir, r.Addr, r.Symbol)
				continue
			}
			want := p.Symbols[printf].Addr
			if r.Symbol != "printf" {
				s, _ := p.Lookup(r.Symbol)
				want = s.Addr
			}
			if got := callTarget(t, p, r.Addr, tc.thumb); got != want {
				t.Errorf("%s: call at %#x goes to %#x, want %s at %#x", tc.dir, r.Addr, got, r.Symbol, want)
			}
			calls++
		}
		if calls < 3 {
			t.Errorf("%s: only %d call relocations", tc.dir, calls)
		}
	}
}

func TestAppliesDataRelocations(t *testing.T) {
	// The -O0 dense switch reads a table of absolute case addresses at 0x28.
	p := loadFile(t, filepath.Join("..", "..", "testdata", "synthetic", "arm", "switch-O0.o"))
	b, _ := p.Read(0x28, 28)
	for i, want := range []uint32{0x44, 0x50, 0x5c, 0x68, 0x74, 0x80, 0x8c} {
		if got := binary.LittleEndian.Uint32(b[4*i:]); got != want {
			t.Errorf("table entry %d = %#x, want %#x", i, got, want)
		}
	}

	// movw/movt pairs load the address of the global origin.
	p = loadFile(t, filepath.Join("..", "..", "testdata", "synthetic", "thumb", "structs-O2.o"))
	origin, ok := p.Lookup("origin")
	if !ok {
		t.Fatal("no origin")
	}
	seen := 0
	for _, r := range p.Relocs {
		if r.Type != rARMThmMovwAbsNC || r.Symbol != "origin" {
			continue
		}
		pair, _ := p.Read(r.Addr, 8) // movw, then movt
		imm := func(b []byte) uint64 {
			hi, lo := uint64(binary.LittleEndian.Uint16(b)), uint64(binary.LittleEndian.Uint16(b[2:]))
			return hi&0xf<<12 | hi>>10&1<<11 | lo>>12&7<<8 | lo&0xff
		}
		if got := imm(pair[4:])<<16 | imm(pair); got != origin.Addr {
			t.Errorf("movw/movt at %#x load %#x, want origin at %#x", r.Addr, got, origin.Addr)
		}
		seen++
	}
	if seen == 0 {
		t.Error("no movw relocations against origin")
	}
}

func TestUnrelocatedKeepsFileBytes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "synthetic", "arm", "switch-O0.o"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := LoadUnrelocated(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Relocs {
		if r.Applied {
			t.Fatalf("relocation at %#x applied", r.Addr)
		}
	}
}
