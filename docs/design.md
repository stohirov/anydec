# Decompile Anything: Design Doc

Oct 27, 2026 · @Sukhrob

## Overview and goals

We build a local-first decompiler (working name `anydec`) that turns firmware and binaries from devices you own into readable C-like code, with no dependency on any hosted AI service. The deterministic engine does all the analysis; an optional AI layer explains results and runs only on models the user controls.

The core idea: a decompiler targets an instruction set, not a device. "Decompile anything" therefore means three things: ingest any container format, support any ISA through a pluggable spec, and recover structure from code with no symbols.

**Goals**

1. **Runs fully offline.** Single static binary, no account, no telemetry, no cloud call in the analysis path.
2. **Broad ISA coverage from day one** by executing Ghidra's open SLEIGH processor specs (Apache 2.0) instead of hand-writing disassemblers.
3. **Firmware-first intake:** unpack update images and flash dumps, not only clean ELF/PE files.
4. **Evidence-backed output:** every recovered statement links back to its address and bytes.
5. **Scriptable:** CLI and API first, so it plugs into any agent, local model or CI job.

**Success criteria for v1**

- Decompiles ARM32/Thumb, AArch64, MIPS32 and x86-64 ELF binaries from a smart-TV root filesystem end to end.
- Loads a raw Cortex-M flash dump, finds its base address and names peripheral registers from an SVD file.
- On a ground-truth corpus, output recompiles for at least 60% of functions and control flow matches the source for at least 80%.

## Non-goals and scope

The tool reads and explains code; it does not break protections. That boundary keeps the project defensible and keeps it useful to repairers, security researchers and owners.

**Non-goals**

- No built-in key extraction, DRM removal, license-check patching or signature bypass.
- No exploit generation or payload tooling.
- Not a sandbox: analysis is static by default; any emulation runs in a separate, opt-in module.
- Not exact source recovery. Names, comments and original file layout are gone from a compiled binary; output is a faithful reading, not the original code.

**Encrypted firmware.** The loader accepts a key the user supplies (for example from a device they already rooted) and decrypts with it. It never searches for or derives keys.

**Legal framing.** Analysis of devices you own for interoperability, repair and security research is broadly accepted, but rules on circumvention and redistribution differ by country. The README should say this plainly, and the tool should never ship third-party firmware in its test corpus.

## Architecture overview

Four stages run in order, and everything after Lift works on the same IR, so new ISAs cost a spec file, not new analysis code. The core is written in Go: one static binary, easy cross-compilation, goroutines for per-function parallelism.

&#91;embedded content: anydec architecture · 4 pipeline stages, store, interfaces, optional AI\]

The AI layer sits outside the pipeline (dashed): it can only read results through the interfaces, so removing it changes nothing about the output.

## Firmware intake and loaders

Intake turns whatever the user has (an update file, a flash dump, an APK) into a tree of typed artifacts, each with a known loader. Most real-world failures happen here, not in decompilation, so intake gets its own module and test corpus.

**Stage 1: identify.** Magic bytes, entropy per 4 KB block, and string scans classify each region. High flat entropy (about 7.9+ bits per byte) flags compressed or encrypted data.

**Stage 2: unpack, recursively.** Each unpacker returns child artifacts that go back through identify.

| Container | Typical source | Approach |
| --- | --- | --- |
| uImage / FIT, Android boot.img | Bootloader + kernel | Native Go parser |
| SquashFS, CramFS, JFFS2, UBI/UBIFS, ext4 | Root filesystems on TVs and routers | Native Go where practical; shell out to `unsquashfs`/`ubireader` as fallback |
| gzip, xz, lzma, lz4, zstd | Compressed sections | Go stdlib and existing libraries |
| Vendor update packages | Samsung, LG, Sony, Android OTA | Plugin per vendor format, user-supplied key if encrypted |
| APK / DEX / JAR | Android TV apps | Hand off to a DEX/JVM decompiler (jadx, CFR); not reimplemented |
| Intel HEX, Motorola S-record, raw `.bin` | MCU flash dumps | Native parser; raw blobs go to the bare-metal path |

**Stage 3: load.** Executable artifacts become a `Program`: segments with addresses and permissions, entry points, symbols, relocations and imports.

| Format | Notes |
| --- | --- |
| ELF (32/64, LE/BE) | Main target for embedded Linux; `debug/elf` in Go stdlib covers parsing |
| PE / COFF | Windows binaries, UEFI modules |
| Mach-O | Apple binaries, lower priority |
| Raw | User or heuristic supplies ISA, endianness and base address (see Bare-metal section) |

**Getting firmware off hardware** stays outside the tool but is documented in a guide: vendor update file first, then UART console, then SPI/eMMC flash read, then JTAG/SWD.

## ISA coverage

We get dozens of architectures by running Ghidra's SLEIGH processor specs in our own Go engine, rather than writing a disassembler per chip. SLEIGH describes each instruction's bit pattern, its text form and its meaning in P-code, a small register-transfer language. Ghidra ships specs for ARM, AArch64, MIPS, PowerPC, x86, RISC-V, AVR, 8051, 68000, SuperH, Xtensa, TriCore and more, under Apache 2.0.

**How it works**

1. **Compile once.** Ghidra's `sleigh` compiler turns `.slaspec` sources into `.sla` files. We vendor the compiled `.sla` files plus their `.pspec` (processor) and `.cspec` (calling-convention) companions, and keep the upstream license notices.
2. **Load in Go.** A `sleigh` package parses `.sla` into decision trees and constructor tables.
3. **Decode.** Walk the decision tree against instruction bytes and context registers (for example ARM vs Thumb mode) to pick a constructor.
4. **Emit.** Produce the assembly text and the P-code ops for that instruction.
5. **Translate.** Convert P-code into our IR (next section), one-to-one at first.

**Adding an architecture** = writing or importing a `.slaspec`. A custom DSP or a TV display-controller core is then supported by the whole pipeline with no other code change.

**Fallback path.** If the SLEIGH runtime is not ready, bind Ghidra's C++ `libdecomp`/`sleigh` library through cgo for decoding only. This keeps progress unblocked but costs the single static binary, so it is a stopgap.

**Java variant.** In Java you could embed Ghidra's own SLEIGH classes directly. That is faster to start but ties the project to Ghidra's internals and a heavy runtime.

## Intermediate representation

All analysis runs on one architecture-neutral IR, so every pass written once works for every ISA. The IR starts as a near copy of P-code and gains structure as passes run.

**Core model**

- **Varnode:** a sized slice of an address space, written `(space, offset, size)`. Spaces: `ram`, `register`, `unique` (temporaries), `const`, plus a `stack` space added after stack analysis.
- **Op:** an opcode with zero or one output varnode and N inputs. About 70 opcodes: copy, load/store, integer and float arithmetic, compares, branches, call/return, plus SSA-only `PHI`, `INDIRECT` (side effects of calls) and `SUBPIECE`/`PIECE` for partial registers.
- **Block:** a straight run of ops with one entry and one exit.
- **Function:** a CFG of blocks, a prototype and a local variable map.

**SSA form.** After the CFG is built, registers and stack slots are renamed into SSA using dominance frontiers (Cytron et al.). Memory stays in a coarse single-version form until alias analysis can split it.

**Design rules**

1. Every IR op keeps a back-pointer to its source instruction address. This powers the evidence links in the output.
2. Passes are pure functions `IR → IR` with a declared list of facts they need and produce. A pass manager orders them and re-runs invalidated ones.
3. Serializable: the IR of each function is stored, so re-opening a project skips decoding and early passes.

```go
type Varnode struct { Space SpaceID; Offset uint64; Size uint8 }
type Op struct {
    Code   Opcode
    Out    *Varnode
    In     []Varnode
    Origin uint64 // source instruction address
}
```

## Analysis pipeline

The pipeline finds code, builds control flow, then simplifies data flow until each function is small enough to structure. Passes run per function in parallel goroutines, with a global queue for facts that cross functions (new call targets, prototypes).

1. **Function discovery.** Seeds: entry point, exported symbols, ELF `.init_array`, exception tables, vector tables on MCUs. Then recursive descent from each seed, plus a linear sweep that scores candidate prologues (for example `push {r4-r7, lr}` on ARM) to catch functions only reached indirectly.
2. **CFG construction.** Split at branch targets and after branches. Track ARM/Thumb mode per address through the SLEIGH context register.
3. **Indirect jumps.** Resolve `switch` jump tables by backward slicing to the bounds check and the table base, then reading the table from the loaded image. Unresolved targets are marked, never guessed.
4. **SSA + simplification.** Constant propagation, copy propagation, dead-code removal, and a rule set of peephole rewrites (for example `x ^ x → 0`, flag computations folded into a single compare).
5. **Stack analysis.** Track the stack pointer delta through each block to turn `sp+offset` accesses into named local slots and to detect stack arguments.
6. **Calling conventions.** Start from the `.cspec` for the ISA (AAPCS on ARM, o32 on MIPS, SysV on x86-64). Infer the actual parameters and returns per function by liveness at entry and use after calls, and propagate signatures interprocedurally until fixed point.
7. **Interprocedural facts.** Build the call graph, mark non-returning functions (`abort`, `panic`), and record which globals each function reads and writes.

Each pass logs what it changed, so a user can step through the pipeline for one function and see why a line looks the way it does.

## Type recovery

Type recovery decides readability more than any other stage: the same logic reads as `buf[i] = 0` or as `*(uint8_t *)(r0 + r4) = 0`. We solve it as constraint inference over SSA values, then seed it with every external fact we can find.

**Constraint inference**

- Each SSA value gets a type variable. Ops add constraints: a value used as a load address is a pointer; `add ptr, const` is a field offset; a signed compare implies a signed integer; float ops imply float.
- Solve with a lattice from "unknown" up through size, integer/pointer/float, signedness, to concrete types (the approach of TIE and Retypd).
- **Struct recovery:** group accesses through one base pointer by offset and size. Fields at `+0x0` (4 bytes), `+0x4` (4 bytes), `+0x8` (pointer) become `struct_A { u32 f0; u32 f4; void *f8; }`, merged across functions that share the pointer.
- **Arrays:** strided access `base + i * size` inside a loop becomes an array of that element type.

**External facts (highest confidence first)**

1. Debug info (DWARF) when present, which is more often than expected in embedded builds.
2. Imported library prototypes: a bundled header database for libc, POSIX, Linux syscalls, OpenSSL, and common SDKs.
3. **Library function matching** for statically linked code: hash function bodies after masking relocated bytes (the FLIRT and Ghidra FunctionID idea), and match against signature packs built from known libc, newlib, mbedTLS and vendor SDK builds.
4. String references and format strings: a `printf`-style call with `"%s:%d"` types its arguments.

Users can override any type, and overrides propagate as hard constraints.

## Structuring and code emission

Structuring turns the CFG back into `if`, `while`, `for`, `switch` and `break`, and uses `goto` only when no structured form exists. We follow the pattern-independent approach of the Dream decompiler and its successors, which avoids most gotos even on optimized code.

**Steps**

1. Compute dominators, post-dominators and natural loops.
2. Structure innermost loops first. Each loop gets a single exit by adding a condition variable when needed.
3. Inside acyclic regions, derive each block's reaching condition as a boolean formula over branch predicates, simplify it, and group blocks into `if`/`else` chains.
4. Recognize `switch` from resolved jump tables and from compare chains on one variable.
5. Last resort: emit a labelled `goto` and mark it in the output.

**Readability passes on the C AST**

- Fold `do { } while` into `for` when an induction variable is found.
- Collapse temporaries used once into their use site.
- Rename variables from evidence: a parameter passed to `open()` becomes `path`; a loop counter becomes `i`.
- Print string and enum constants instead of addresses and magic numbers.

**Output formats.** C-like text with address comments, a JSON AST for tools, and an HTML view where clicking a line highlights its assembly.

## Bare-metal and embedded support

Raw flash dumps have no headers, so the tool must infer what an ELF file would state: ISA, endianness, load address and memory map. This is where "anything" is hardest, and where a dedicated path pays off.

**Inference steps**

1. **ISA and endianness:** decode sample windows with every candidate SLEIGH spec and score by valid-instruction rate and branch-target plausibility (the idea behind `cpu_rec`).
2. **Base address:** collect absolute pointers found in the image and string offsets, then pick the base where the most pointers land on string starts or function prologues.
3. **Vector table (Cortex-M):** the first word is the initial stack pointer and the next ones are handler addresses with the Thumb bit set. A valid table confirms the base and seeds function discovery.
4. **Memory map:** load a CMSIS-SVD file for the chip to map peripheral addresses, so `*(volatile u32 *)0x40011004` prints as `USART1->DR`. Without SVD, cluster accesses into probable peripheral blocks.

**Embedded patterns to recognize**

- RTOS kernels (FreeRTOS, Zephyr, ThreadX): task creation calls, queue APIs, scheduler entry.
- Bootloader stages and relocation loops that copy code from flash to RAM, so code is analyzed at its run address.
- Interrupt handlers and memory-mapped I/O marked `volatile`.

**Inputs a user can supply** when heuristics fail: ISA, base address, a linker-map style region list, or an SVD file.

## Optional AI layer

AI is a client of the engine, never part of it: every result is produced deterministically first, and a model only reads, explains and asks follow-up queries. So no AI provider can stop a user from analyzing their own device; at worst the explanation step is unavailable and the plain output remains.

**Design**

- **Local by default.** Ships with adapters for OpenAI-compatible local servers (llama.cpp, vLLM, Ollama), so models such as self-hosted Qwen run on the user's machine with the user's own settings.
- **MCP server.** Exposes tools like `list_functions`, `decompile(addr)`, `xrefs(addr)`, `strings(filter)`, `rename(addr, name)`. Any MCP client can attach; hosted agents are one option, not a requirement.
- **Evidence contract.** Every AI claim must cite addresses or IR ops returned by tools. Answers without citations are flagged in the UI.
- **Model tasks that help most:** naming functions and variables, summarizing a function, spotting known protocols or crypto constants, and proposing struct layouts for the engine to verify.

**Hosted agents.** Their behavior is set by their providers, and the tool does not try to influence it. Clear, evidence-based tool output and an honest task description work best with them. When a hosted agent declines, the user switches to a local model or works directly in the CLI.

## Interfaces and storage

The CLI is the primary interface; every other surface calls the same Go API. A project is one SQLite file next to the input, so analysis survives restarts and can be shared.

**CLI**

```
anydec unpack firmware.bin -o extracted/
anydec open extracted/usr/bin/tvservice --project tv.adb
anydec funcs tv.adb --filter net
anydec decompile tv.adb 0x401a20 --format c
anydec raw dump.bin --isa ARM:LE:32:Cortex --base auto --svd stm32f4.svd
anydec serve tv.adb --mcp   # MCP server for local or hosted agents
```

**Project database (SQLite)**

| Table | Holds |
| --- | --- |
| `artifacts` | Unpack tree: parent, offset, type, hash |
| `segments`, `symbols` | Loaded memory map and names |
| `functions` | Address, prototype, status, user overrides |
| `ir_cache` | Serialized IR per function per pass version |
| `types` | Recovered and user-defined types |
| `annotations` | Renames, comments, bookmarks with author and time |

**API.** A Go package (`anydec/engine`) plus a gRPC or JSON-RPC server for other languages, including a Java client for your existing services.

**UI (later).** A local web UI served by `anydec serve`: function list, side-by-side C and assembly, call graph, hex view.

## Testing and evaluation

We measure correctness against binaries we compile ourselves, where the source is known. Third-party firmware is used only for manual smoke tests on the developer's own devices and is never committed.

**Ground-truth corpus**

- Open-source C projects (BusyBox, coreutils, mbedTLS, FreeRTOS demos) built for each target ISA with GCC and Clang at `-O0`, `-O2` and `-Os`, stripped and unstripped. That gives source, symbols and DWARF to score against.
- A synthetic suite of small functions per feature: each loop shape, switch style, struct pattern and calling convention.

**Test layers**

| Layer | Checks |
| --- | --- |
| Decoder | Disassembly matches `objdump` / Ghidra output instruction by instruction |
| Lifter | Emulate IR and native code on random inputs; register and memory state must match |
| CFG | Function boundaries and edges match DWARF and compiler output |
| Types | Recovered signatures and struct layouts vs DWARF |
| Output | Decompiled C recompiles, and the recompiled function passes the original's tests |

**Metrics tracked per release:** function-boundary F1, percent of functions that recompile, goto count per 1,000 lines, type accuracy vs DWARF, and analysis time per MB.

## Roadmap and milestones

The plan reaches readable C on ARM in phase 3 and only then widens to types and firmware, so the riskiest engine work is proven before breadth is added.

&#91;embedded content: roadmap · 5 phases, 4 gates\]

Phases 1 to 3 hold most of the engineering effort; durations depend on weekly hours and are left open until phase 1 is measured.

## Risks and open questions

The largest risk is scope: a production decompiler is years of work, so each phase must ship something usable on its own.

| Risk | Mitigation |
| --- | --- |
| SLEIGH runtime in Go takes longer than planned | cgo binding to Ghidra's C++ library as a temporary decoder |
| Type recovery quality stays low on optimized code | Lean on library matching and DWARF first; expose easy manual overrides |
| Vendor firmware formats change or are encrypted | Plugin per format; user-supplied keys only; document limits honestly |
| Upstream license obligations | Keep Apache 2.0 notices for vendored SLEIGH specs; pick Apache 2.0 or MIT for the project |
| Misuse for cracking or DRM removal | No such features; clear README scope; responsible-disclosure policy for anything found |

**Open questions**

- [ ] Pure Go SLEIGH runtime, or start with cgo and replace it later?
- [ ] Which first device anchors v1: a specific TV model, a router, or an STM32 board?
- [ ] Is a dynamic analysis module (emulation via Unicorn or QEMU user mode) in scope for v1?
- [ ] Open source from day one, or after the IR and pass APIs stabilize?
