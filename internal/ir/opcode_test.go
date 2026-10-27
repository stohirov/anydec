package ir

import "testing"

func TestEveryOpcodeHasAUniqueName(t *testing.T) {
	seen := map[string]Opcode{}
	for o := OpInvalid; o < opcodeCount; o++ {
		name := o.String()
		if name == "UNKNOWN" {
			t.Errorf("opcode %d has no name", o)
			continue
		}
		if prev, ok := seen[name]; ok {
			t.Errorf("opcodes %d and %d share name %q", prev, o, name)
		}
		seen[name] = o
	}
}

func TestVarnodeString(t *testing.T) {
	v := Varnode{Space: SpaceRegister, Offset: 0x20, Size: 4}
	if got, want := v.String(), "(register, 0x20, 4)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
