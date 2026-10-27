// Package ai is an optional client of the engine, never part of it: it reads
// results through the same interfaces as any other caller. It hosts the MCP
// server (list_functions, decompile, xrefs, strings, rename) and adapters for
// OpenAI-compatible local model servers. Removing it changes nothing about the
// decompiler output.
package ai
