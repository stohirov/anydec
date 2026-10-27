// Package store persists a project as one SQLite file: the unpack tree,
// memory map, functions, cached IR, types and user annotations.
//
// The driver is pure Go (modernc.org/sqlite), so the binary stays static
// with CGO_ENABLED=0.
package store

import (
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

// Schema is the DDL applied when a project database is created.
//
//go:embed schema.sql
var Schema string

// SchemaVersion is recorded in the meta table; Open refuses other
// versions.
const SchemaVersion = "1"

// ErrNotProject is returned when a file is not an anydec project.
var ErrNotProject = errors.New("not an anydec project")

// DB is an open project database.
type DB struct {
	db *sql.DB
}

// IsProject reports whether the file at path starts like a SQLite
// database.
func IsProject(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 16)
	n, _ := f.Read(head)
	return n == 16 && string(head) == "SQLite format 3\x00"
}

// Create makes a new project database at path, which must not exist.
func Create(path string) (*DB, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("%s already exists", path)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(Schema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`INSERT INTO meta (key, value) VALUES ('schema_version', ?)`, SchemaVersion); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db: db}, nil
}

// Open opens an existing project database.
func Open(path string) (*DB, error) {
	if !IsProject(path) {
		return nil, fmt.Errorf("%s: %w", path, ErrNotProject)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	var v string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&v); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, ErrNotProject)
	}
	if v != SchemaVersion {
		db.Close()
		return nil, fmt.Errorf("%s: project schema version %s, this anydec reads %s", path, v, SchemaVersion)
	}
	return &DB{db: db}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// Artifact is one input file or unpacked piece of one.
type Artifact struct {
	ID       int64
	ParentID int64 // 0 for a top-level input
	Offset   uint64
	Kind     string
	Path     string
	SHA256   string
	Data     []byte
}

// Segment is a loaded memory range.
type Segment struct {
	Name    string
	Address uint64
	Size    uint64
	Perms   string
}

// Symbol is a named address.
type Symbol struct {
	Address uint64
	Name    string
	Kind    string
	Source  string
}

// Function is what the project records about one function.
type Function struct {
	Address   uint64
	Name      string
	Prototype string
	Status    string
}

// Tx runs fn in a transaction, committing when it returns nil.
func (d *DB) Tx(fn func(*Tx) error) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(&Tx{tx}); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Tx writes to a project inside a transaction.
type Tx struct{ tx *sql.Tx }

func nullable(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// AddArtifact records an artifact and returns its id.
func (t *Tx) AddArtifact(a Artifact) (int64, error) {
	r, err := t.tx.Exec(`INSERT INTO artifacts (parent_id, offset, kind, path, sha256, data) VALUES (?, ?, ?, ?, ?, ?)`,
		nullable(a.ParentID), int64(a.Offset), a.Kind, a.Path, a.SHA256, a.Data)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

// AddSegment records a segment of an artifact.
func (t *Tx) AddSegment(artifact int64, s Segment) error {
	_, err := t.tx.Exec(`INSERT INTO segments (artifact_id, name, address, size, perms) VALUES (?, ?, ?, ?, ?)`,
		artifact, s.Name, int64(s.Address), int64(s.Size), s.Perms)
	return err
}

// AddSymbol records a symbol of an artifact.
func (t *Tx) AddSymbol(artifact int64, s Symbol) error {
	_, err := t.tx.Exec(`INSERT INTO symbols (artifact_id, address, name, kind, source) VALUES (?, ?, ?, ?, ?)`,
		artifact, int64(s.Address), s.Name, s.Kind, s.Source)
	return err
}

// PutFunction records or replaces a function.
func (t *Tx) PutFunction(f Function) error {
	_, err := t.tx.Exec(`INSERT INTO functions (address, name, prototype, status) VALUES (?, ?, ?, ?)
		ON CONFLICT(address) DO UPDATE SET name = excluded.name, prototype = excluded.prototype, status = excluded.status`,
		int64(f.Address), f.Name, f.Prototype, f.Status)
	return err
}

// PutIR caches a function's serialized IR for one pass and version.
func (t *Tx) PutIR(addr uint64, pass string, version int, ir []byte) error {
	_, err := t.tx.Exec(`INSERT OR REPLACE INTO ir_cache (function_address, pass, pass_version, ir) VALUES (?, ?, ?, ?)`,
		int64(addr), pass, version, ir)
	return err
}

// Input returns the first top-level artifact, with its bytes.
func (d *DB) Input() (Artifact, error) {
	var a Artifact
	var off int64
	var path sql.NullString
	err := d.db.QueryRow(`SELECT id, offset, kind, path, sha256, data FROM artifacts WHERE parent_id IS NULL ORDER BY id LIMIT 1`).
		Scan(&a.ID, &off, &a.Kind, &path, &a.SHA256, &a.Data)
	if errors.Is(err, sql.ErrNoRows) {
		return a, errors.New("project has no input")
	}
	a.Offset, a.Path = uint64(off), path.String
	return a, err
}

// Functions returns every recorded function by address.
func (d *DB) Functions() ([]Function, error) {
	rows, err := d.db.Query(`SELECT address, name, COALESCE(prototype, ''), status FROM functions ORDER BY address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Function
	for rows.Next() {
		var f Function
		var addr int64
		if err := rows.Scan(&addr, &f.Name, &f.Prototype, &f.Status); err != nil {
			return nil, err
		}
		f.Address = uint64(addr)
		out = append(out, f)
	}
	return out, rows.Err()
}

// IR returns the cached IR of every function for one pass and version,
// by address.
func (d *DB) IR(pass string, version int) (map[uint64][]byte, error) {
	rows, err := d.db.Query(`SELECT function_address, ir FROM ir_cache WHERE pass = ? AND pass_version = ?`, pass, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint64][]byte{}
	for rows.Next() {
		var addr int64
		var ir []byte
		if err := rows.Scan(&addr, &ir); err != nil {
			return nil, err
		}
		out[uint64(addr)] = ir
	}
	return out, rows.Err()
}
