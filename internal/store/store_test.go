package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAndOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.adb")
	db, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Tx(func(tx *Tx) error {
		id, err := tx.AddArtifact(Artifact{Kind: "elf", Path: "a.o", SHA256: "00", Data: []byte{1, 2, 3}})
		if err != nil {
			return err
		}
		if err := tx.AddSegment(id, Segment{Name: ".text", Address: 0, Size: 3, Perms: "r-x"}); err != nil {
			return err
		}
		if err := tx.AddSymbol(id, Symbol{Address: 1 << 63, Name: "high", Kind: "function", Source: "elf"}); err != nil {
			return err
		}
		if err := tx.PutFunction(Function{Address: 1 << 63, Name: "high", Prototype: "void high(void)", Status: "decompiled"}); err != nil {
			return err
		}
		if err := tx.PutFunction(Function{Address: 1 << 63, Name: "high", Prototype: "int high(void)", Status: "warnings"}); err != nil {
			return err
		}
		return tx.PutIR(1<<63, "cfg", 1, []byte("ir"))
	})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	if _, err := Create(path); err == nil {
		t.Error("Create overwrote an existing file")
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	in, err := db.Input()
	if err != nil || in.Path != "a.o" || string(in.Data) != "\x01\x02\x03" {
		t.Errorf("Input() = %+v, %v", in, err)
	}
	fns, err := db.Functions()
	if err != nil || len(fns) != 1 || fns[0].Address != 1<<63 || fns[0].Prototype != "int high(void)" {
		t.Errorf("Functions() = %+v, %v", fns, err)
	}
	irs, err := db.IR("cfg", 1)
	if err != nil || string(irs[1<<63]) != "ir" {
		t.Errorf("IR() = %v, %v", irs, err)
	}
	if irs, _ := db.IR("cfg", 2); len(irs) != 0 {
		t.Errorf("IR of another version: %v", irs)
	}
}

func TestOpenRejectsOtherFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(path, []byte("not a database at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrNotProject) {
		t.Errorf("Open(text file) = %v", err)
	}
}
