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
		{"decompile"},              // missing input
		{"decompile", "a", "b", "c"},
		{"open", "a.o"},      // missing --project
		{"version", "extra"}, // unexpected positional
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

func TestDecompileCommand(t *testing.T) {
	obj := filepath.Join("..", "..", "testdata", "synthetic", "arm", "arith-O0.o")
	code, out, errOut := run("decompile", obj, "clamp")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"uint32_t clamp(uint32_t a1, uint32_t a2, uint32_t a3)", "return "} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "add(") {
		t.Errorf("one function asked, others printed:\n%s", out)
	}
	code, out, _ = run("decompile", obj, "0xbc", "--addrs")
	if code != 0 || !strings.Contains(out, "clamp") || !strings.Contains(out, "/* 0x") {
		t.Errorf("by address with --addrs: exit %d\n%s", code, out)
	}
	code, out, _ = run("decompile", obj)
	if code != 0 || !strings.Contains(out, "#include <stdint.h>") || !strings.Contains(out, "uint32_t add(") {
		t.Errorf("whole file: exit %d\n%s", code, out)
	}
	if code, _, errOut := run("decompile", obj, "nope"); code != 1 || !strings.Contains(errOut, "no function") {
		t.Errorf("unknown function: exit %d, stderr %q", code, errOut)
	}
}

func TestProjectCommands(t *testing.T) {
	obj := filepath.Join("..", "..", "testdata", "synthetic", "thumb", "calls-O0.o")
	project := filepath.Join(t.TempDir(), "calls.adb")
	code, out, errOut := run("open", obj, "--project", project)
	if code != 0 {
		t.Fatalf("open: exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "functions") {
		t.Errorf("open printed %q", out)
	}
	if code, _, _ := run("open", obj, "--project", project); code != 1 {
		t.Errorf("open over an existing project: exit %d, want 1", code)
	}
	code, out, errOut = run("funcs", project, "--filter", "fib")
	if code != 0 || !strings.Contains(out, "fib") {
		t.Errorf("funcs on project: exit %d: %s%s", code, out, errOut)
	}
	code, out, errOut = run("decompile", project, "fib")
	if code != 0 || !strings.Contains(out, "fib(") {
		t.Errorf("decompile from project: exit %d: %s%s", code, out, errOut)
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
	code, out, errOut = run("ir", obj, "--func", "dense", "--ssa")
	if code != 0 || !strings.Contains(out, "dense(r0_in) -> 4") || !strings.Contains(out, "PHI") {
		t.Errorf("--ssa: exit %d: %s%s", code, out, errOut)
	}
	if code, _, _ := run("ir", obj); code != 2 {
		t.Errorf("missing --func: exit %d, want 2", code)
	}
	if code, _, _ := run("ir", obj, "--func", "0x1234"); code != 1 {
		t.Errorf("unknown address: exit %d, want 1", code)
	}
}
