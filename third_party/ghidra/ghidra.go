// Package ghidra embeds the compiled SLEIGH processor specs vendored from
// Ghidra, in Ghidra's own Processors/<arch>/data/languages layout.
package ghidra

import "embed"

// Processors holds every vendored processor module.
//
//go:embed Processors
var Processors embed.FS
