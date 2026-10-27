// Package structure turns a CFG back into if, while, for, switch and break,
// following the pattern-independent approach of the Dream decompiler. It falls
// back to a labelled goto only when no structured form exists.
package structure
