# Test corpus

Everything here is built from **open-source code we compile ourselves**, so the source, symbols and DWARF are available to score against.

- **Ground truth:** projects such as BusyBox, coreutils, mbedTLS and FreeRTOS demos, built for each target ISA (ARM32/Thumb, AArch64, MIPS32, x86-64) with GCC and Clang at `-O0`, `-O2` and `-Os`, both stripped and unstripped.
- **Synthetic:** one small function per feature, covering each loop shape, switch style, struct pattern and calling convention.

**Never commit third-party firmware or vendor binaries.** Keep anything you use for local smoke tests in `/samples/`, which git ignores.

## Synthetic corpus

`synthetic/src/*.c` is compiled by `make corpus` for each target in `CORPUS_TARGETS` (ARMv7-A, Thumb-2 for Cortex-M3, and Cortex-M4F with hard float) at `-O0`, `-O2` and `-Os`. Each relocatable object `synthetic/<target>/<name>-<opt>.o` is committed together with its `llvm-objdump` listing (`.objdump`), so the tests need no cross toolchain.

Two tests use it:

- `engine/corpus_test.go` decodes every object and compares each instruction with the objdump listing: boundaries must match exactly, and mnemonics and operands must match after syntax normalization or a documented Ghidra divergence.
- `engine/pcode_test.go` runs the P-code of integer leaf functions in a small interpreter and checks the results against the C semantics.

Rebuild the corpus after changing a source file, and commit the objects and listings together.
