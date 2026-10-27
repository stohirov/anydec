package engine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stohirov/decompile-anything/internal/irexec"
	"github.com/stohirov/decompile-anything/internal/loader"
)

// The decompiler gate: every -O0 corpus object is decompiled to C, the C
// is compiled again for the object's own target, and each recompiled
// function runs on the recorded vectors in the IR interpreter (whose
// lifting the TestIRMatchesNative gate checks against native runs). A
// function passes when every vector does. Most functions must pass.

// recompileTargets maps corpus directories to clang target triples.
var recompileTargets = map[string]string{
	"arm":      "armv7a-none-eabi",
	"thumb":    "thumbv7m-none-eabi",
	"thumb-hf": "thumbv7em-none-eabihf",
	"aarch64":  "aarch64-none-elf",
	"x86-64":   "x86_64-none-elf",
}

// recompileGate is the share of -O0 functions that must pass.
const recompileGate = 0.9

func clang(t *testing.T) string {
	cc := os.Getenv("CORPUS_CC")
	if cc == "" {
		cc = "clang"
	}
	path, err := exec.LookPath(cc)
	if err != nil {
		t.Skipf("no %s to recompile decompiled C: %v", cc, err)
	}
	return path
}

// recompile decompiles obj and compiles the C for triple.
func recompile(t *testing.T, cc, obj, triple string) (src string, out []byte, err error) {
	data, err := os.ReadFile(obj)
	if err != nil {
		return "", nil, err
	}
	prog, err := Load(data)
	if err != nil {
		return "", nil, err
	}
	a, err := Analyze(prog, false)
	if err != nil {
		return "", nil, err
	}
	src, err = a.Source(false)
	if err != nil {
		return "", nil, err
	}
	dir := t.TempDir()
	cfile := filepath.Join(dir, "out.c")
	ofile := filepath.Join(dir, "out.o")
	if err := os.WriteFile(cfile, []byte(src), 0o644); err != nil {
		return src, nil, err
	}
	cmd := exec.Command(cc, "--target="+triple, "-O0", "-std=gnu11", "-ffreestanding", "-fno-builtin",
		"-ffp-contract=off", "-fno-asynchronous-unwind-tables", "-w", "-c", cfile, "-o", ofile)
	if msg, err := cmd.CombinedOutput(); err != nil {
		lines := strings.Split(string(msg), "\n")
		var errs []string
		for _, l := range lines {
			if strings.Contains(l, "error:") {
				errs = append(errs, l[strings.Index(l, "error:"):])
			}
		}
		if len(errs) > 5 {
			errs = append(errs[:5], fmt.Sprintf("... %d more", len(errs)-5))
		}
		return src, nil, fmt.Errorf("%v: %s", err, strings.Join(errs, "; "))
	}
	out, err = os.ReadFile(ofile)
	return src, out, err
}

func TestDecompiledCRecompiles(t *testing.T) {
	cc := clang(t)
	byFn := map[string][]vector{}
	for _, v := range readVectors(t) {
		byFn[v.Fn] = append(byFn[v.Fn], v)
	}
	opt := os.Getenv("RECOMPILE_OPT") // O2 or Os report on optimized code; the gate is O0
	if opt == "" {
		opt = "O0"
	}
	objs, err := filepath.Glob(filepath.Join("..", "testdata", "synthetic", "*", "*-"+opt+".o"))
	if err != nil {
		t.Fatal(err)
	}
	total, passed := 0, 0
	var failures []string
	for _, obj := range objs {
		dir := filepath.Base(filepath.Dir(obj))
		triple, ok := recompileTargets[dir]
		if !ok {
			continue
		}
		name, _ := filepath.Rel(filepath.Join("..", "testdata", "synthetic"), obj)
		src, data, err := recompile(t, cc, obj, triple)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			if os.Getenv("DUMP_C") != "" {
				t.Log(src)
			}
			continue
		}
		prog, err := Load(data)
		if err != nil {
			t.Fatalf("%s: recompiled object: %v", name, err)
		}
		a, err := Analyze(prog, false)
		if err != nil {
			t.Fatalf("%s: recompiled object: %v", name, err)
		}
		orig, _ := os.ReadFile(obj)
		op, _ := Load(orig)
		for _, s := range op.Symbols {
			if s.Kind != loader.SymFunction || len(byFn[s.Name]) == 0 {
				continue
			}
			total++
			fn := a.Function(0, s.Name)
			if fn == nil {
				failures = append(failures, fmt.Sprintf("%s %s: missing from the recompiled object", name, s.Name))
				continue
			}
			bad := ""
			for _, v := range byFn[s.Name] {
				diff, err := execute(t, a, fn, v, dir)
				if err != nil {
					diff = err.Error()
					if errors.Is(err, irexec.ErrUnsupported) {
						diff = "unsupported: " + diff
					}
				}
				if diff != "" && execDivergenceFor(dir, v) == nil {
					bad = fmt.Sprintf("%v: %s", v.Args, diff)
					break
				}
			}
			if bad != "" {
				failures = append(failures, fmt.Sprintf("%s %s%s", name, s.Name, bad))
				continue
			}
			passed++
		}
		if os.Getenv("DUMP_C") != "" {
			t.Logf("%s:\n%s", name, src)
		}
	}
	sort.Strings(failures)
	for _, f := range failures {
		t.Log(f)
	}
	t.Logf("%d of %d -%s functions recompile and pass their vectors", passed, total, opt)
	if opt == "O0" && (total == 0 || float64(passed) < recompileGate*float64(total)) {
		t.Errorf("gate: %d of %d pass, want at least %.0f%%", passed, total, 100*recompileGate)
	}
}
