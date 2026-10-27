// Package store persists a project as one SQLite file: the unpack tree,
// memory map, functions, cached IR, types and user annotations.
//
// The driver must be pure Go (for example modernc.org/sqlite) so the binary
// stays static with CGO_ENABLED=0.
package store

import _ "embed"

// Schema is the DDL applied when a project database is created.
//
//go:embed schema.sql
var Schema string
