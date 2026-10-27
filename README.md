# anydec

A local-first decompiler that turns firmware and binaries from devices you own into readable C-like code. It needs no hosted AI service: a deterministic engine does all the analysis, and an optional AI layer explains results using models you run yourself.

> **Status:** phase 2 (lifting and control flow). An ELF loader that applies object relocations and a pure-Go SLEIGH runtime decode ARM, Thumb, AArch64, x86 and MIPS code, checked against llvm-objdump on a synthetic corpus (MIPS by hand-encoded tests only). P-code is lifted to an architecture-neutral IR, and the engine discovers functions (including in stripped code), builds their control-flow graphs and resolves jump tables. Running the lifted IR reproduces native results for every corpus function. `identify`, `disasm`, `funcs` and `ir` work; the other commands parse their arguments and report "not implemented yet". See [the design doc](docs/design.md) for the plan.

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
make test         # go test ./...
make check        # vet + gofmt check + tests
make corpus       # rebuild testdata/synthetic (needs clang with ARM, AArch64 and x86 targets)
```

## Usage

```sh
anydec identify firmware.bin
anydec disasm extracted/usr/bin/tvservice --func main
anydec funcs extracted/usr/bin/tvservice --filter net   # a binary, until projects exist
anydec ir extracted/usr/bin/tvservice --func main       # lifted IR and CFG
anydec unpack firmware.bin -o extracted/
anydec open extracted/usr/bin/tvservice --project tv.adb
anydec funcs tv.adb --filter net
anydec decompile tv.adb 0x401a20 --format c
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
| `internal/analysis` | Function discovery, CFG, jump tables; later SSA, simplification, stack, calling conventions |
| `internal/irexec` | IR interpreter the tests use to check lifting against native runs |
| `internal/typerec` | Constraint-based type, struct and array recovery |
| `internal/structure` | CFG back into `if`/`while`/`switch` |
| `internal/emit` | C text, JSON AST, HTML output |
| `internal/baremetal` | ISA, base address and peripheral inference for raw dumps |
| `internal/store` | SQLite project database |
| `internal/ai` | Optional MCP server and local-model adapters, outside the pipeline |
| `third_party/ghidra` | Vendored compiled SLEIGH specs and their license notices |
| `testdata` | Ground-truth corpus built from open-source code |

## License

MIT for this project; see [LICENSE](LICENSE). Vendored Ghidra SLEIGH specs keep their Apache 2.0 license; see [third_party/ghidra](third_party/ghidra).
