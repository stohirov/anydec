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
| AARCH64 | `AARCH64.ldefs`, `AARCH64.sla`, `AARCH64BE.sla`, `AARCH64.pspec`, `AARCH64.cspec`, `AARCH64_ilp32.cspec` | `AARCH64:{LE,BE}:64:v8A`, `AARCH64:{LE,BE}:32:ilp32` |
| x86 | `x86.ldefs`, `x86.sla`, `x86-64.sla`, `x86.pspec`, `x86-64.pspec`, `x86-64-compat32.pspec`, `x86-16.pspec`, `x86-16-real.pspec`, `x86gcc.cspec`, `x86-64-gcc.cspec`, `x86-16.cspec` | `x86:LE:32:default`, `x86:LE:64:default`, `x86:LE:64:compat32`, `x86:LE:32:System Management Mode`, `x86:LE:16:{Real,Protected} Mode` |
| MIPS | `mips.ldefs`, `mips32{be,le}.sla`, `mips64{be,le}.sla`, `mips32.pspec`, `mips32_16e.pspec`, `mips32micro.pspec`, `mips64.pspec`, `mips64_16e.pspec`, `mips64micro.pspec`, `mips64R6.pspec`, `mips32{be,le}.cspec`, `mips64{be,le}.cspec` | `MIPS:{BE,LE}:32:{default,16e,micro}`, `MIPS:{BE,LE}:64:{default,16e,micro,R6,64-32addr,micro64-32addr,64-32R6addr}` |

Only each language's default (or gcc) compiler spec is vendored. `.ldefs` entries naming other `.cspec` files still load: the decoder reads only `.sla` and `.pspec`, and the decompiler takes calling conventions from the first vendored `.cspec` with compiler id `default` or `gcc` (`internal/abi`).

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
