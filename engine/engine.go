// Package engine is the public Go API of anydec. The CLI, the MCP server and
// any RPC surface all call through it, so every interface sees the same
// results.
package engine

import (
	"errors"

	"github.com/stohirov/decompile-anything/internal/intake"
)

// Version is overridden at build time with -ldflags "-X ...engine.Version=v".
var Version = "dev"

// ErrNotImplemented marks pipeline stages that are designed but not built yet.
var ErrNotImplemented = errors.New("not implemented yet")

// Identification is the result of classifying one input.
type Identification = intake.Report

// Identify classifies data by magic bytes and per-block entropy.
func Identify(data []byte) Identification {
	return intake.Identify(data)
}
