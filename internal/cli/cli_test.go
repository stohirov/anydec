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
