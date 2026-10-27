# anydec

A local-first decompiler that turns firmware and binaries from devices you own into readable C-like code. It needs no hosted AI service: a deterministic engine does all the analysis, and an optional AI layer explains results using models you run yourself.

> **Status:** phase 3 (first decompiler). An ELF loader and a pure-Go SLEIGH runtime decode ARM, Thumb, AArch64, x86 and MIPS code. Their output is checked against llvm-objdump on a synthetic corpus (MIPS only by hand-encoded tests). P-code is lifted to an architecture-neutral IR, and the engine discovers functions and builds their control-flow graphs. The decompiler puts each function into SSA form and simplifies it, turns stack slots into variables, and infers prototypes from the vendored Ghidra calling conventions. It then structures the control flow and prints C. Every `-O0` corpus function decompiles to C that recompiles for its target and reproduces the native results. Projects are saved as SQLite files. `identify`, `disasm`, `funcs`, `ir`, `open` and `decompile` (C output) work; the other commands parse their arguments and report "not implemented yet". See [the design doc](docs/design.md) for the plan.

## Goals

- **Runs fully offline.** One static binary, with no account, no telemetry and no cloud calls during analysis.
- **Broad ISA coverage.** It runs Ghidra's open SLEIGH processor specs (Apache 2.0) instead of a hand-written disassembler per chip.
- **Firmware-first intake.** It unpacks update images and flash dumps, not only clean ELF/PE files.
- **Evidence-backed output.** Every recovered statement links back to its address and bytes.
- **Scriptable.** The CLI and Go API come first, plus an MCP server for local or hosted agents.

## Scope

anydec reads and explains code. It does not break protections.

- No key extraction, DRM removal, license-check patching or signature bypass.
- No exploit generation or payload tooling.
- Encrypted firmware is decrypted only with a key **you** supply. The tool never searches for keys or derives them.
- Analysis is static. Any emulation will live in a separate module you have to opt into.

## Legal

Analyzing devices you own for interoperability, repair and security research is broadly accepted. Rules on circumventing protections and redistributing firmware differ by country, so check the law where you live. This repository never ships third-party firmware, and its test corpus is built only from open-source code compiled by the project.

## Build

Requires Go 1.27+.

```sh
make build        # static binary at bin/anydec (CGO_ENABLED=0)
make test         # go test ./... (the decompiler gate needs clang with ARM, AArch64 and x86 targets; it is skipped without one)
make check        # vet + gofmt check + tests
make corpus       # rebuild testdata/synthetic (needs clang with ARM, AArch64 and x86 targets)
```

## Usage

```sh
anydec identify firmware.bin
anydec disasm extracted/usr/bin/tvservice --func main
anydec ir extracted/usr/bin/tvservice --func main       # lifted IR and CFG (--ssa: SSA form)
anydec open extracted/usr/bin/tvservice --project tv.adb
anydec funcs tv.adb --filter net                        # a project or a binary
anydec decompile tv.adb main                            # one function as C (--addrs: address comments)
anydec decompile tv.adb > tv.c                          # every function as one compilable C file
anydec unpack firmware.bin -o extracted/
anydec raw dump.bin --isa ARM:LE:32:Cortex --base auto --svd stm32f4.svd
anydec serve tv.adb --mcp
```

## Layout

| Path | Stage |
| --- | --- |
| `cmd/anydec` | CLI entry point |
| `engine` | Public Go API. Every interface calls through it |
| `internal/intake` | Identify and recursively unpack containers |
| `internal/loader` | ELF, PE, Mach-O and raw images into a `Program` |
| `internal/sleigh` | Pure-Go SLEIGH runtime: decode bytes, emit P-code |
| `internal/lift` | P-code into IR; the only stage that knows about SLEIGH |
| `internal/ir` | Architecture-neutral IR (varnodes, ops, blocks, functions) and op semantics |
| `internal/analysis` | Function discovery, CFG, jump tables |
| `internal/ssa` | SSA form, simplification, stack promotion, prototype inference and call binding |
| `internal/abi` | Calling conventions read from Ghidra compiler specs |
| `internal/irexec` | IR interpreter the tests use to check lifting and recompiled output against native runs |
| `internal/typerec` | Constraint-based type, struct and array recovery |
| `internal/structure` | CFG back into `if`/`while`/`switch` |
| `internal/emit` | C text (JSON AST and HTML later) |
| `internal/baremetal` | ISA, base address and peripheral inference for raw dumps |
| `internal/store` | SQLite project database (pure Go driver) |
| `internal/ai` | Optional MCP server and local-model adapters, outside the pipeline |
| `third_party/ghidra` | Vendored compiled SLEIGH specs and their license notices |
| `testdata` | Ground-truth corpus built from open-source code |

## License

MIT for this project; see [LICENSE](LICENSE). Vendored Ghidra SLEIGH specs keep their Apache 2.0 license; see [third_party/ghidra](third_party/ghidra).
