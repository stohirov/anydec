package sleigh

import (
	"encoding/binary"
	"errors"
	"testing"
)

// Hand-encoded instructions for ISAs the synthetic corpus does not cover
// (no MIPS compiler) or covers in one byte order only. Expected text
// follows the display sections of the Ghidra specs: register names from
// mips.sinc, signed hex immediates, absolute branch targets.

func words(big bool, ws ...uint32) []byte {
	b := make([]byte, 4*len(ws))
	for i, w := range ws {
		if big {
			binary.BigEndian.PutUint32(b[4*i:], w)
		} else {
			binary.LittleEndian.PutUint32(b[4*i:], w)
		}
	}
	return b
}

func TestDecodeMIPS(t *testing.T) {
	prog := []struct {
		word uint32
		text string
	}{
		{0x27bdffe0, "addiu sp, sp, -0x20"},  // 0x1000
		{0x10800003, "beq a0, zero, 0x1014"}, // 0x1004: offset 3 words past the delay slot
		{0x00851021, "addu v0, a0, a1"},      // 0x1008: delay slot
		{0x0c100040, "jal 0x400100"},         // 0x100c
		{0x8fbf001c, "lw ra, 0x1c(sp)"},      // 0x1010: delay slot
		{0x03e00008, "jr ra"},                // 0x1014
		{0x00000000, "nop"},                  // 0x1018: delay slot
	}
	ws := make([]uint32, len(prog))
	for i, p := range prog {
		ws[i] = p.word
	}
	for _, c := range []struct {
		id  string
		big bool
	}{{"MIPS:BE:32:default", true}, {"MIPS:LE:32:default", false}} {
		t.Run(c.id, func(t *testing.T) {
			l := loadARM(t, c.id)
			d := l.NewDecoder(memBytes{0x1000, words(c.big, ws...)})
			reg := func(v Varnode) string { return l.Spec.RegisterName(v.Space, v.Offset, v.Size) }
			for i, p := range prog {
				addr := 0x1000 + 4*uint64(i)
				in, err := d.Decode(addr)
				if err != nil {
					t.Fatalf("%#x: %v", addr, err)
				}
				if in.String() != p.text || in.Length != 4 {
					t.Errorf("%#x: %q (%d bytes), want %q", addr, in, in.Length, p.text)
				}
			}

			// A branch's p-code includes its delay slot, which runs
			// before the branch is taken.
			in, ops, err := d.Translate(0x1004)
			if err != nil {
				t.Fatal(err)
			}
			if in.Length != 4 || in.DelaySlot != 4 {
				t.Errorf("beq: length %d, delay slot %d; want 4 and 4", in.Length, in.DelaySlot)
			}
			addAt, branchAt := -1, -1
			for i, op := range ops {
				if op.Op == OpIntAdd && op.Out != nil && reg(*op.Out) == "v0" {
					addAt = i
				}
				if op.Op == OpCBranch && op.In[0].Space == l.Spec.DefaultSpace && op.In[0].Offset == 0x1014 {
					branchAt = i
				}
			}
			if addAt < 0 || branchAt < addAt {
				t.Errorf("beq: want v0 = a0 + a1 before CBRANCH 0x1014; ops %v", ops)
			}

			// jal links past its delay slot and loads ra in the slot
			// before calling.
			_, ops, err = d.Translate(0x100c)
			if err != nil {
				t.Fatal(err)
			}
			link, load, call := -1, -1, -1
			for i, op := range ops {
				switch {
				case op.Op == OpCopy && op.Out != nil && reg(*op.Out) == "ra" && op.In[0].Offset == 0x1014:
					link = i
				case op.Op == OpLoad && op.Out != nil:
					load = i
				case op.Op == OpCall && op.In[0].Offset == 0x400100:
					call = i
				}
			}
			if link < 0 || load < 0 || call < load {
				t.Errorf("jal: want ra = 0x1014, then the delay-slot load, then CALL 0x400100; ops %v", ops)
			}

			_, ops, err = d.Translate(0x1014)
			if err != nil {
				t.Fatal(err)
			}
			if last := ops[len(ops)-1]; last.Op != OpReturn {
				t.Errorf("jr ra: last op %v, want RETURN", last)
			}
		})
	}
}

// AArch64 instructions are little-endian in both byte orders; the BE
// language only changes data accesses.
func TestDecodeAArch64BigEndian(t *testing.T) {
	code := words(false, 0x8b020020, 0xf9400420) // add x0,x1,x2; ldr x0,[x1, #0x8]
	for _, id := range []string{"AARCH64:LE:64:v8A", "AARCH64:BE:64:v8A"} {
		l := loadARM(t, id)
		d := l.NewDecoder(memBytes{0, code})
		for i, want := range []string{"add x0, x1, x2", "ldr x0, [x1, #0x8]"} {
			in, err := d.Decode(4 * uint64(i))
			if err != nil || in.String() != want {
				t.Errorf("%s %#x: %v, %v; want %q", id, 4*i, in, err, want)
			}
		}
		if l.Spec.DefaultSpace.BigEndian != (id == "AARCH64:BE:64:v8A") {
			t.Errorf("%s: ram big-endian %v", id, l.Spec.DefaultSpace.BigEndian)
		}
	}
}

// Some AArch64 SIMD encodings decode, but their p-code reads an operand
// whose constructor exports nothing. Translate must fail, not panic.
func TestTranslateOperandWithoutExport(t *testing.T) {
	d := loadARM(t, "AARCH64:LE:64:v8A").NewDecoder(memBytes{0, words(false, 0x0f43fa05)})
	in, err := d.Decode(0)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, _, err := d.Translate(0); !errors.Is(err, ErrBadInstruction) {
		t.Errorf("translate %s: %v, want ErrBadInstruction", in, err)
	}
}

// The same bytes decode differently in 32- and 64-bit x86: 0x48 is dec eax
// in one and a REX.W prefix in the other.
func TestDecodeX86Modes(t *testing.T) {
	code := []byte{0x48, 0x89, 0xc8} // dec eax; mov eax,ecx | mov rax,rcx
	for _, c := range []struct {
		id   string
		want []string
	}{
		{"x86:LE:32:default", []string{"DEC EAX", "MOV EAX,ECX"}},
		{"x86:LE:64:default", []string{"MOV RAX,RCX"}},
	} {
		d := loadARM(t, c.id).NewDecoder(memBytes{0, code})
		addr := uint64(0)
		for _, want := range c.want {
			in, err := d.Decode(addr)
			if err != nil {
				t.Fatalf("%s %#x: %v", c.id, addr, err)
			}
			if in.String() != want {
				t.Errorf("%s %#x: %q, want %q", c.id, addr, in, want)
			}
			addr += uint64(in.Length)
		}
		if addr != 3 {
			t.Errorf("%s: decoded %d bytes, want 3", c.id, addr)
		}
	}
}
