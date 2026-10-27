// Package sleigh executes Ghidra's compiled SLEIGH processor specs (.sla,
// with .pspec and .cspec companions) in pure Go: it parses a spec into decision
// trees and constructor tables, decodes instruction bytes against context
// registers, and emits assembly text plus P-code ops.
//
// Compiled specs are vendored under third_party/ghidra with their Apache 2.0
// notices.
package sleigh
