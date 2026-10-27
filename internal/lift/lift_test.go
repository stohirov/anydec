package lift

import (
	"fmt"
	"testing"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/sleigh"
	"github.com/stohirov/decompile-anything/third_party/ghidra"
)

type memory map[uint64][]byte

func (m memory) Read(addr uint64, n int) ([]byte, error) {
	for base, b := range m {
		if addr >= base && addr < base+uint64(len(b)) {
			return b[addr-base:][:min(n, int(base+uint64(len(b))-addr))], nil
		}
	}
	return nil, fmt.Errorf("unmapped %#x", addr)
}

func armLifter(t *testing.T, code []byte) *Lifter {
	t.Helper()
	lang, err := sleigh.LoadLanguage(ghidra.Processors, "ARM:LE:32:v8")
	if err != nil {
		t.Fatal(err)
	}
	return New("ARM:LE:32:v8", lang.NewDecoder(memory{0x1000: code}))
}

func TestLiftARM(t *testing.T) {
	// ldr r0, [r1, #4]; bx lr
	l := armLifter(t, []byte{0x04, 0x00, 0x91, 0xe5, 0x1e, 0xff, 0x2f, 0xe1})
	in, err := l.Lift(0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if in.Text != "ldr r0,[r1,#0x4]" || in.Length != 4 {
		t.Errorf("insn %q length %d", in.Text, in.Length)
	}
	var load *ir.Op
	for i := range in.Ops {
		if in.Ops[i].Origin != 0x1000 {
			t.Errorf("op %d origin %#x", i, in.Ops[i].Origin)
		}
		if in.Ops[i].Code == ir.OpLoad {
			load = &in.Ops[i]
		}
	}
	if load == nil {
		t.Fatalf("no LOAD in %v", in.Ops)
	}
	if load.In[0] != (ir.Varnode{Space: ir.SpaceConst, Offset: uint64(ir.SpaceRAM), Size: load.In[0].Size}) {
		t.Errorf("LOAD space operand %v, want ram", load.In[0])
	}
	r0, _ := l.Register("r0")
	if *load.Out != r0 {
		t.Errorf("LOAD writes %v, want r0 %v", load.Out, r0)
	}
	if got := l.Arch().FormatVarnode(r0); got != "r0" {
		t.Errorf("r0 prints as %q", got)
	}

	ret, err := l.Lift(0x1004)
	if err != nil {
		t.Fatal(err)
	}
	if last := ret.Ops[len(ret.Ops)-1]; last.Code != ir.OpReturn {
		t.Errorf("bx lr ends in %s", last.Code)
	}
}

func TestLiftBadBytes(t *testing.T) {
	l := armLifter(t, []byte{0xff, 0xff, 0xff, 0xff})
	if in, err := l.Lift(0x1000); err == nil {
		t.Errorf("lifted %v from undefined encoding", in)
	}
}

func TestEveryPcodeOpcodeMaps(t *testing.T) {
	for op := sleigh.OpCopy; op <= sleigh.OpLzCount; op++ {
		switch op {
		case sleigh.OpZPull, sleigh.OpSPull: // no IR equivalent yet
			continue
		}
		if _, ok := opcodes[op]; !ok && op.String() != fmt.Sprintf("OPCODE(%d)", int(op)) {
			t.Errorf("%s has no IR opcode", op)
		}
	}
}
