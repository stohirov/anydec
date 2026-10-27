# Vendored Ghidra SLEIGH specs

This directory holds compiled SLEIGH processor specs from [Ghidra](https://github.com/NationalSecurityAgency/ghidra), which are licensed under Apache 2.0 (see [LICENSE](LICENSE) and each module's `LICENSE.txt`):

- `.sla`: compiled with Ghidra's `sleigh` compiler from upstream `.slaspec` sources
- `.ldefs`: language definitions, mapping language ids such as `ARM:LE:32:v8` to their `.sla` and `.pspec`
- `.pspec`: processor description (context registers, default symbols)
- `.cspec`: calling conventions

`ghidra.go` embeds `Processors/` into the binary, so anydec needs no files at run time.

## What is vendored

| Module | Files | Languages |
| --- | --- | --- |
| ARM | `ARM.ldefs`, `ARM8_{le,be}.sla`, `ARM7_{le,be}.sla`, `ARMt.pspec`, `ARMtTHUMB.pspec`, `ARMCortex.pspec`, `ARM.cspec` | `ARM:{LE,BE}:32:v8`, `ARM:{LE,BE}:32:v8T`, `ARM:{LE,BE}:32:Cortex` |

Languages in an `.ldefs` file whose `.sla` is not vendored are ignored.

## Rules

- Keep upstream's `LICENSE` and `NOTICE` files next to the specs, unmodified. (The Ghidra release ships no `NOTICE` file; its top-level `LICENSE` is the Apache 2.0 text.)
- Record the Ghidra release tag every spec was compiled from in `VERSION`.
- Use the upstream directory layout (`Processors/<arch>/data/languages/`) so specs can be diffed against new releases.
- Copy specs unmodified, even where they contain known bugs; the decoder harness in `engine/corpus_test.go` documents those as named divergences.

## Adding an architecture

1. Download the Ghidra release named in `VERSION` and copy `Ghidra/Processors/<arch>/data/languages/` files (`.ldefs`, the `.sla` files its languages name, their `.pspec` and `.cspec`) plus the module's `LICENSE.txt` into `Processors/<arch>/`.
2. Add a row to the table above.
3. Map the ELF machine to its language id in `internal/loader/elf.go` if it is not there yet.
