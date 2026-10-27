package sleigh

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/stohirov/decompile-anything/third_party/ghidra"
)

type memBytes struct {
	base uint64
	b    []byte
}

func (m memBytes) Read(addr uint64, n int) ([]byte, error) {
	if addr < m.base || addr >= m.base+uint64(len(m.b)) {
		return nil, errors.New("unmapped")
	}
	off := addr - m.base
	return m.b[off:min(off+uint64(n), uint64(len(m.b)))], nil
}

func TestParsePacked(t *testing.T) {
	// <sleigh version=4 bigendian=true name="x"><spaces/></sleigh>, with
	// an extended id (eSpaceUnique = 46 needs two header bytes).
	raw := []byte{
		0x40 | 0x20 | (eSleigh >> 7), 0x80 | eSleigh&0x7f,
		0xc0 | 0x20 | (aVersion >> 7), 0x80 | aVersion&0x7f, typeSignedPos<<4 | 1, 0x80 | 4,
		0xc0 | 0x20 | (aBigendian >> 7), 0x80 | aBigendian&0x7f, typeBool<<4 | 1,
		0xc0 | aName, typeString<<4 | 1, 0x80 | 1, 'x',
		0x40 | 0x20 | (eSpaceUnique >> 7), 0x80 | eSpaceUnique&0x7f,
		0x80 | 0x20 | (eSpaceUnique >> 7), 0x80 | eSpaceUnique&0x7f,
		0x80 | 0x20 | (eSleigh >> 7), 0x80 | eSleigh&0x7f,
	}
	root, err := parsePacked(raw)
	if err != nil {
		t.Fatal(err)
	}
	if root.id != eSleigh || len(root.kids) != 1 || root.kids[0].id != eSpaceUnique {
		t.Fatalf("tree: id %d with %d children", root.id, len(root.kids))
	}
	err = catchDecode(func() {
		if v := root.int(aVersion); v != 4 {
			t.Errorf("version %d", v)
		}
		if !root.bool(aBigendian) || root.str(aName) != "x" {
			t.Errorf("bigendian %v name %q", root.bool(aBigendian), root.str(aName))
		}
		root.uint(aVersion) // wrong type
	})
	if !errors.Is(err, errDecode) {
		t.Errorf("reading a signed attribute as unsigned: %v", err)
	}

	for name, bad := range map[string][]byte{
		"truncated":      raw[:len(raw)-1],
		"wrong close":    append(append([]byte{}, raw[:len(raw)-2]...), 0x80|0x20|(eSpaces>>7), 0x80|eSpaces&0x7f),
		"trailing bytes": append(append([]byte{}, raw...), 0x40|1),
	} {
		if _, err := parsePacked(bad); !errors.Is(err, errDecode) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func catchDecode(f func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errDecode
		}
	}()
	f()
	return nil
}

func TestReadSLAHeader(t *testing.T) {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte{0x40 | 1, 0x80 | 1})
	zw.Close()
	if _, err := readSLA(append([]byte("sla\x03"), z.Bytes()...)); err == nil || !strings.Contains(err.Error(), "version 3") {
		t.Errorf("old version: %v", err)
	}
	if _, err := readSLA([]byte("<?xml")); !errors.Is(err, errDecode) {
		t.Errorf("XML .sla: %v", err)
	}
	if _, err := readSLA(append([]byte("sla\x04"), z.Bytes()...)); err != nil {
		t.Errorf("valid stream: %v", err)
	}
}

func ghidraFS() fs.FS { return ghidra.Processors }

func loadARM(t *testing.T, id string) *Language {
	t.Helper()
	l, err := LoadLanguage(ghidra.Processors, id)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLanguages(t *testing.T) {
	infos, err := Languages(ghidra.Processors)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, l := range infos {
		have[l.ID] = true
	}
	for _, id := range []string{"ARM:LE:32:v8", "ARM:BE:32:v8", "ARM:LE:32:v8T", "ARM:LE:32:Cortex"} {
		if !have[id] {
			t.Errorf("%s not listed; have %v", id, have)
		}
	}
	if have["ARM:LE:32:v4"] {
		t.Error("listed a language whose .sla is not vendored")
	}
	if _, err := LoadLanguage(ghidra.Processors, "Z80:LE:16:default"); !errors.Is(err, ErrUnknownLanguage) {
		t.Errorf("unknown language: %v", err)
	}
}

func TestDecodeARMAndThumb(t *testing.T) {
	l := loadARM(t, "ARM:LE:32:v8")
	code := []byte{
		0x00, 0x00, 0x81, 0xe0, // ARM: add r0,r1,r0
		0x1e, 0xff, 0x2f, 0xe1, // ARM: bx lr
		0x08, 0x44, // Thumb: add r0,r1
		0x14, 0xbf, // Thumb: ite ne
		0x90, 0xfb, 0xf1, 0xf0, // Thumb: sdiv.ne r0,r0,r1
		0x00, 0x20, // Thumb: mov.eq r0,#0x0
	}
	d := l.NewDecoder(memBytes{0x1000, code})
	if err := d.SetContext("TMode", 0x1008, 0, 1); err != nil {
		t.Fatal(err)
	}
	want := []string{"add r0,r1,r0", "bx lr", "add r0,r1", "ite ne", "sdiv.ne r0,r0,r1", "mov.eq r0,#0x0"}
	addr := uint64(0x1000)
	for _, w := range want {
		in, err := d.Decode(addr)
		if err != nil {
			t.Fatalf("%#x: %v", addr, err)
		}
		if in.String() != w {
			t.Errorf("%#x: %q, want %q", addr, in, w)
		}
		addr += uint64(in.Length)
	}
	if _, err := d.Decode(0x1001); !errors.Is(err, ErrBadInstruction) {
		t.Errorf("misaligned: %v", err)
	}
	if err := d.SetContext("NoSuchVar", 0, 0, 1); err == nil {
		t.Error("unknown context variable accepted")
	}
}

func TestDecodeTruncated(t *testing.T) {
	d := loadARM(t, "ARM:LE:32:v8").NewDecoder(memBytes{0, []byte{0x00, 0x00}})
	if _, err := d.Decode(0); !errors.Is(err, ErrBadInstruction) {
		t.Errorf("2 bytes of an ARM instruction: %v", err)
	}
}

func TestDecodeBigEndian(t *testing.T) {
	d := loadARM(t, "ARM:BE:32:v8").NewDecoder(memBytes{0, []byte{0xe0, 0x81, 0x00, 0x00}})
	in, err := d.Decode(0)
	if err != nil || in.String() != "add r0,r1,r0" {
		t.Errorf("big-endian add: %v, %v", in, err)
	}
}

func TestTranslate(t *testing.T) {
	l := loadARM(t, "ARM:LE:32:v8")
	code := []byte{
		0x00, 0x00, 0x81, 0xe0, // add r0,r1,r0
		0x04, 0x30, 0x90, 0xe4, // ldr r3,[r0],#0x4
		0xfb, 0xff, 0xff, 0x1a, // bne 0xffc
	}
	d := l.NewDecoder(memBytes{0x1000, code})
	reg := func(v Varnode) string {
		if n := l.Spec.RegisterName(v.Space, v.Offset, v.Size); n != "" {
			return n
		}
		return v.String()
	}

	_, ops, err := d.Translate(0x1000)
	if err != nil {
		t.Fatal(err)
	}
	last := ops[len(ops)-1]
	var add *PcodeOp
	for i := range ops {
		if ops[i].Op == OpIntAdd {
			add = &ops[i]
		}
	}
	if add == nil || reg(*add.Out) != "r0" || reg(add.In[0]) != "r1" || reg(add.In[1]) != "r0" {
		t.Errorf("add: no INT_ADD r0 = r1 + r0 in %v", ops)
	}
	if last.Op != OpIntEqual {
		t.Errorf("add ends with %s, want the Z flag computation", last.Op)
	}

	_, ops, err = d.Translate(0x1004)
	if err != nil {
		t.Fatal(err)
	}
	load := ops[len(ops)-1]
	if load.Op != OpLoad || l.Spec.Spaces[load.In[0].Offset] != l.Spec.DefaultSpace || reg(*load.Out) != "r3" {
		t.Errorf("ldr: last op %v, want r3 = LOAD ram", load)
	}

	_, ops, err = d.Translate(0x1008)
	if err != nil {
		t.Fatal(err)
	}
	br := ops[len(ops)-1]
	if br.Op != OpCBranch || br.In[0].Space != l.Spec.DefaultSpace || br.In[0].Offset != 0xffc {
		t.Errorf("bne: last op %v, want CBRANCH to ram 0xffc", br)
	}
}

func TestContextChangePoints(t *testing.T) {
	db := newContextDB(1)
	db.defaults[0] = 0x1
	db.setRegion(0x200, 0x300, 0, 0xf0, 0x20) // explicitly set at 0x200
	db.setChangePoint(0x100, 0, 0xf0, 0x50)   // flows until 0x200, and no further
	get := func(a uint64) uint32 {
		v := make([]uint32, 1)
		db.get(a, v)
		return v[0]
	}
	for _, c := range []struct {
		addr uint64
		want uint32
	}{{0x0, 0x01}, {0x100, 0x51}, {0x1ff, 0x51}, {0x200, 0x21}, {0x2ff, 0x21}, {0x300, 0x01}} {
		if got := get(c.addr); got != c.want {
			t.Errorf("context at %#x = %#x, want %#x", c.addr, got, c.want)
		}
	}
}
