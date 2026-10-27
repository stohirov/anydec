# Test corpus

Everything here is built from **open-source code we compile ourselves**, so the source, symbols and DWARF are available to score against.

- **Ground truth:** projects such as BusyBox, coreutils, mbedTLS and FreeRTOS demos, built for each target ISA (ARM32/Thumb, AArch64, MIPS32, x86-64) with GCC and Clang at `-O0`, `-O2` and `-Os`, both stripped and unstripped.
- **Synthetic:** one small function per feature, covering each loop shape, switch style, struct pattern and calling convention.

**Never commit third-party firmware or vendor binaries.** Keep anything you use for local smoke tests in `/samples/`, which git ignores.
