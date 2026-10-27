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
