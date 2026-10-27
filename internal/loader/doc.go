// Package loader turns executable artifacts into a Program: segments with
// addresses and permissions, entry points, symbols, relocations and imports.
// Formats: ELF (32/64, LE/BE), PE/COFF, Mach-O, and raw images whose ISA,
// endianness and base address come from the user or the baremetal package.
package loader
