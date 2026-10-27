package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// A project reopened from its database decompiles exactly as the binary
// it was made from: the cached IR round-trips.
func TestProjectRoundTrip(t *testing.T) {
	obj := filepath.Join("..", "testdata", "synthetic", "arm", "jumps-O0.o")
	data, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "jumps.adb")
	p, err := CreateProject(path, obj, data, true)
	if err != nil {
		t.Fatal(err)
	}
	want, err := p.Analysis.Source(true)
	if err != nil {
		t.Fatal(err)
	}
	fns, err := p.Functions()
	if err != nil {
		t.Fatal(err)
	}
	if len(fns) != len(p.Analysis.Functions) || fns[0].Prototype == "" || fns[0].Status == "" {
		t.Errorf("stored functions %+v", fns)
	}
	p.Close()

	if !IsProject(path) || IsProject(obj) {
		t.Fatal("IsProject misclassifies files")
	}
	q, err := OpenProject(path)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	got, err := q.Analysis.Source(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("reopened project decompiles differently:\n--- reopened\n%s\n--- original\n%s", got, want)
	}
	if _, err := CreateProject(path, obj, data, true); err == nil {
		t.Error("CreateProject replaced an existing file")
	}
}
