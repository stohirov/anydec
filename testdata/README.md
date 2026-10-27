# Test corpus

Everything here is built from **open-source code we compile ourselves**, so the source, symbols and DWARF are available to score against.

- **Ground truth:** projects such as BusyBox, coreutils, mbedTLS and FreeRTOS demos, built for each target ISA (ARM32/Thumb, AArch64, MIPS32, x86-64) with GCC and Clang at `-O0`, `-O2` and `-Os`, both stripped and unstripped.
- **Synthetic:** one small function per feature, covering each loop shape, switch style, struct pattern and calling convention.

**Never commit third-party firmware or vendor binaries.** Keep anything you use for local smoke tests in `/samples/`, which git ignores.

## Synthetic corpus

`synthetic/src/*.c` is compiled by `make corpus` for each target in `CORPUS_TARGETS` (ARMv7-A, Thumb-2 for Cortex-M3, Cortex-M4F with hard float, AArch64 and x86-64) at `-O0`, `-O2` and `-Os`. Each relocatable object `synthetic/<target>/<name>-<opt>.o` is committed together with its `llvm-objdump` listing (`.objdump`), so the tests need no cross toolchain.

`synthetic/asm/<target>.s` lists instructions compilers rarely emit (prefixes, VEX, x87, segment overrides); `make corpus` assembles each into `synthetic/<target>/stress-asm.o` with its listing. MIPS has no corpus because Apple clang has no MIPS backend; `internal/sleigh/isa_test.go` checks hand-encoded MIPS instead.

`synthetic/harness/harness.c` is the native reference: `make vectors` compiles it with `synthetic/src/*.c` for the host, calls every function on seeded random inputs, and writes the inputs and the results the host computed to `synthetic/vectors.jsonl`.

Tests that use the corpus:

- `engine/corpus_test.go` decodes every object and compares each instruction with the objdump listing: boundaries must match exactly, and mnemonics and operands must match after syntax normalization or a documented Ghidra divergence.
- `engine/exec_test.go` lifts every object, discovers its functions, and runs each one in the IR interpreter on the recorded inputs, passing arguments as the target's calling convention does. Results must match the native ones to the bit, except where a vendored spec is known to differ from the hardware (named divergences).
- `engine/analyze_test.go` checks that discovered functions match the symbol table, with symbols and without, that every CFG is well formed, and that jump tables resolve.

Rebuild the corpus after changing a source file, then the vectors, and commit the objects, listings and vectors together.
