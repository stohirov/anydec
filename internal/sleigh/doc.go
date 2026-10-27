// Package sleigh executes Ghidra's compiled SLEIGH processor specs (.sla,
// with .pspec and .cspec companions) in pure Go: it parses a spec into decision
// trees and constructor tables, decodes instruction bytes against context
// registers, and emits assembly text plus P-code ops.
//
// Compiled specs are vendored under third_party/ghidra with their Apache 2.0
// notices.
//
// The decoding runtime (sleigh.cc, slghsymbol.cc, slghpattern.cc,
// slghpatexpress.cc, semantics.cc, context.cc and globalcontext.cc in
// Ghidra's decompiler, tag Ghidra_12.2_build) is ported here from C++ to Go.
// Ghidra is Copyright the National Security Agency and licensed under the
// Apache License 2.0; see third_party/ghidra/LICENSE. The port keeps the
// original's structure and names so the two can be compared; it changes the
// data structures to Go idioms and leaves out the spec compiler.
package sleigh
