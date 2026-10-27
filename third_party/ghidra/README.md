# Vendored Ghidra SLEIGH specs

This directory will hold compiled SLEIGH processor specs from [Ghidra](https://github.com/NationalSecurityAgency/ghidra), which are licensed under Apache 2.0:

- `.sla`: compiled with Ghidra's `sleigh` compiler from upstream `.slaspec` sources
- `.pspec`: processor description (context registers, default symbols)
- `.cspec`: calling conventions

## Rules

- Keep upstream's `LICENSE` and `NOTICE` files next to the specs, unmodified.
- Record the Ghidra release tag every spec was compiled from in `VERSION`.
- Use the upstream directory layout (`Processors/<arch>/data/languages/`) so specs can be diffed against new releases.
