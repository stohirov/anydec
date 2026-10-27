package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/stohirov/decompile-anything/internal/ir"
	"github.com/stohirov/decompile-anything/internal/store"
)

// Project is an analysis saved in a project database: one SQLite file
// holding the input, its memory map and symbols, every function's
// prototype, and the IR of every function, so reopening skips discovery.
type Project struct {
	Path     string
	Analysis *Analysis
	db       *store.DB
}

// IsProject reports whether path holds a project database.
func IsProject(path string) bool { return store.IsProject(path) }

// CreateProject analyzes data, the bytes of the file at input, and saves
// the result in a new project database at path.
func CreateProject(path, input string, data []byte, sweep bool) (*Project, error) {
	prog, err := Load(data)
	if err != nil {
		return nil, err
	}
	a, err := Analyze(prog, sweep)
	if err != nil {
		return nil, err
	}
	u, err := a.unit(false)
	if err != nil {
		return nil, err
	}
	db, err := store.Create(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	err = db.Tx(func(tx *store.Tx) error {
		id, err := tx.AddArtifact(store.Artifact{Kind: prog.Format, Path: input, SHA256: hex.EncodeToString(sum[:]), Data: data})
		if err != nil {
			return err
		}
		for _, s := range prog.Segments {
			if err := tx.AddSegment(id, store.Segment{Name: s.Name, Address: s.Addr, Size: uint64(len(s.Data)), Perms: s.Perm.String()}); err != nil {
				return err
			}
		}
		for _, s := range prog.Symbols {
			if err := tx.AddSymbol(id, store.Symbol{Address: s.Addr, Name: s.Name, Kind: string(s.Kind), Source: prog.Format}); err != nil {
				return err
			}
		}
		for i, fn := range a.Functions {
			status := "decompiled"
			if len(fn.Warnings) > 0 || len(u.Funcs[i].Warnings) > 0 {
				status = "warnings"
			}
			f := store.Function{Address: fn.Entry, Name: fn.Name, Prototype: u.Signature(u.Funcs[i]), Status: status}
			if err := tx.PutFunction(f); err != nil {
				return err
			}
			enc, err := fn.Encode()
			if err != nil {
				return fmt.Errorf("%s: %w", fn.Name, err)
			}
			if err := tx.PutIR(fn.Entry, "cfg", ir.EncodingVersion, enc); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Project{Path: path, Analysis: a, db: db}, nil
}

// OpenProject reopens a project database, rebuilding the analysis from
// its cached IR (or analyzing the stored input again when the cache is
// from another IR version).
func OpenProject(path string) (*Project, error) {
	db, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	p, err := openProject(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Path = path
	return p, nil
}

func openProject(db *store.DB) (*Project, error) {
	in, err := db.Input()
	if err != nil {
		return nil, err
	}
	prog, err := Load(in.Data)
	if err != nil {
		return nil, err
	}
	cached, err := db.IR("cfg", ir.EncodingVersion)
	if err != nil {
		return nil, err
	}
	var a *Analysis
	if len(cached) == 0 {
		if a, err = Analyze(prog, true); err != nil {
			return nil, err
		}
	} else {
		if a, _, err = newAnalysis(prog); err != nil {
			return nil, err
		}
		for addr, data := range cached {
			fn, err := ir.DecodeFunction(data)
			if err != nil {
				return nil, fmt.Errorf("cached IR of %#x: %w", addr, err)
			}
			a.Functions = append(a.Functions, fn)
		}
		sort.Slice(a.Functions, func(i, j int) bool { return a.Functions[i].Entry < a.Functions[j].Entry })
	}
	return &Project{Analysis: a, db: db}, nil
}

// Functions returns what the project records about each function.
func (p *Project) Functions() ([]store.Function, error) { return p.db.Functions() }

// Close closes the project database.
func (p *Project) Close() error { return p.db.Close() }
