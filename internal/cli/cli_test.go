package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestIdentifyCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.bin")
	if err := os.WriteFile(path, []byte("\x7fELF\x01\x01\x01"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run("identify", path)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "kind: elf") {
		t.Errorf("output missing kind:\n%s", out)
	}
}

func TestFlagsAfterPositionalArgs(t *testing.T) {
	code, _, errOut := run("decompile", "tv.adb", "0x401a20", "--format", "json")
	if code != 1 || !strings.Contains(errOut, "not implemented") {
		t.Errorf("exit %d, stderr %q; want parsed args reaching the engine", code, errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	tests := [][]string{
		{"unpack", "firmware.bin"}, // missing -o
		{"raw", "dump.bin"},        // missing --isa
		{"decompile", "tv.adb"},    // missing address
		{"version", "extra"},       // unexpected positional
	}
	for _, args := range tests {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	if code, _, _ := run("nope"); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}

func TestBadAddress(t *testing.T) {
	code, _, errOut := run("decompile", "tv.adb", "main")
	if code != 1 || !strings.Contains(errOut, "invalid address") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

func TestDisasmCommand(t *testing.T) {
	obj := filepath.Join("..", "..", "testdata", "synthetic", "thumb", "arith-O2.o")
	code, out, errOut := run("disasm", obj, "--func", "sdiv")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"<sdiv>:", "ite ne", "sdiv.ne r0,r0,r1", "bx lr"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "<add>") {
		t.Errorf("--func sdiv printed other functions:\n%s", out)
	}
	if code, _, _ := run("disasm", obj, "--func", "nope"); code != 1 {
		t.Errorf("unknown function: exit %d, want 1", code)
	}
}

func TestFuncsCommand(t *testing.T) {
	obj := filepath.Join("..", "..", "testdata", "synthetic", "arm", "jumps-O2.o")
	code, out, errOut := run("funcs", obj, "--filter", "switch")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"offset_switch  (1 jump table(s))", "byte_switch"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "alu") {
		t.Errorf("--filter switch listed alu:\n%s", out)
	}
}

func TestIRCommand(t *testing.T) {
	obj := filepath.Join("..", "..", "testdata", "synthetic", "thumb", "switch-O0.o")
	code, out, errOut := run("ir", obj, "--func", "dense")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"dense at 0x0:", "jump table at 0xe: 0->0x1a 1->0x20", "tbb [pc,r1]", "BRANCHIND", "RETURN"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if code, _, _ := run("ir", obj); code != 2 {
		t.Errorf("missing --func: exit %d, want 2", code)
	}
	if code, _, _ := run("ir", obj, "--func", "0x1234"); code != 1 {
		t.Errorf("unknown address: exit %d, want 1", code)
	}
}
