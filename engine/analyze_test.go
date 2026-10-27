package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stohirov/decompile-anything/internal/loader"
)

// corpusObjects returns the compiled corpus objects with C functions.
func corpusObjects(t *testing.T) []string {
	t.Helper()
	objs, err := filepath.Glob(filepath.Join("..", "testdata", "synthetic", "*", "*.o"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, o := range objs {
		if !strings.HasPrefix(filepath.Base(o), "stress-asm") {
			out = append(out, o)
		}
	}
	return out
}

func loadObject(t *testing.T, path string) *Program {
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

func symbolEntries(p *Program) map[uint64]string {
	want := map[uint64]string{}
	for _, s := range p.Symbols {
		if s.Kind == loader.SymFunction {
			want[s.Addr] = s.Name
		}
	}
	return want
}

// indirectTailCalls are functions whose only unresolved indirect jump is
// a call through a function pointer.
var indirectTailCalls = map[string]bool{"apply": true}

func TestDiscoveryMatchesSymbols(t *testing.T) {
	for _, obj := range corpusObjects(t) {
		name, _ := filepath.Rel(filepath.Join("..", "testdata", "synthetic"), obj)
		p := loadObject(t, obj)
		a, err := Analyze(p, false)
		if err != nil {
			t.Fatal(err)
		}
		want := symbolEntries(p)
		if len(a.Functions) != len(want) {
			t.Errorf("%s: %d functions, want %d", name, len(a.Functions), len(want))
		}
		for _, fn := range a.Functions {
			if want[fn.Entry] != fn.Name {
				t.Errorf("%s: function %s at %#x is not a symbol", name, fn.Name, fn.Entry)
			}
			if err := fn.Verify(); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			for _, w := range fn.Warnings {
				t.Errorf("%s: %s: %s", name, fn.Name, w)
			}
			if len(fn.Unresolved) > 0 && !indirectTailCalls[fn.Name] {
				t.Errorf("%s: %s has unresolved indirect jumps at %#x", name, fn.Name, fn.Unresolved)
			}
		}
	}
}

func TestStrippedDiscovery(t *testing.T) {
	for _, obj := range corpusObjects(t) {
		name, _ := filepath.Rel(filepath.Join("..", "testdata", "synthetic"), obj)
		p := loadObject(t, obj)
		want := symbolEntries(p)
		// Strip every symbol but the imports, which relocations name.
		stripped := *p
		stripped.Symbols = nil
		for _, s := range p.Symbols {
			if s.Kind == loader.SymImport {
				stripped.Symbols = append(stripped.Symbols, s)
			}
		}
		a, err := Analyze(&stripped, true)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, fn := range a.Functions {
			if _, ok := want[fn.Entry]; ok {
				found++
			} else {
				t.Errorf("%s: stripped discovery found %s, which is not a function", name, fn.Name)
			}
			if err := fn.Verify(); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		if found != len(want) {
			t.Errorf("%s: stripped discovery found %d of %d functions", name, found, len(want))
		}
	}
}

func TestJumpTables(t *testing.T) {
	// Case bodies of dense() at -O0, in case order, by their constant.
	for _, dir := range []string{"arm", "thumb", "thumb-hf", "x86-64"} {
		p := loadObject(t, filepath.Join("..", "testdata", "synthetic", dir, "switch-O0.o"))
		a, err := Analyze(p, false)
		if err != nil {
			t.Fatal(err)
		}
		fn := a.Function(0, "dense")
		if fn == nil || len(fn.JumpTables) != 1 {
			t.Fatalf("%s: dense has no jump table: %+v", dir, fn)
		}
		jt := fn.JumpTables[0]
		if len(jt.Cases) != 7 {
			t.Fatalf("%s: %d cases, want 7: %+v", dir, len(jt.Cases), jt.Cases)
		}
		seen := map[uint64]bool{}
		for i, c := range jt.Cases {
			if c.Value != int64(i) {
				t.Errorf("%s: case %d has value %d", dir, i, c.Value)
			}
			if seen[c.Target] {
				t.Errorf("%s: target %#x repeats", dir, c.Target)
			}
			seen[c.Target] = true
		}
	}
}
