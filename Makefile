VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/stohirov/decompile-anything/engine.Version=$(VERSION)

.PHONY: build test vet fmt check clean corpus vectors

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/anydec ./cmd/anydec

test:
	go test ./...

vet:
	go vet ./...

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

check: vet fmt test

clean:
	rm -rf bin

# Synthetic corpus: our own C sources cross-compiled to relocatable objects,
# with llvm-objdump listings as the decoder's reference. Rebuild with
# `make corpus` after changing testdata/synthetic/src; the outputs are
# committed so tests need no cross toolchain.
CORPUS_CC ?= clang
OBJDUMP ?= $(shell command -v llvm-objdump || echo objdump)
CORPUS_TARGETS := arm:armv7a-none-eabi thumb:thumbv7m-none-eabi thumb-hf:thumbv7em-none-eabihf aarch64:aarch64-none-elf x86-64:x86_64-none-elf
CORPUS_OPTS := O0 O2 Os

corpus: corpus-asm
	@for t in $(CORPUS_TARGETS); do \
		dir=testdata/synthetic/$${t%%:*}; triple=$${t#*:}; mkdir -p $$dir; \
		for src in testdata/synthetic/src/*.c; do \
			name=$$(basename $$src .c); \
			for o in $(CORPUS_OPTS); do \
				obj=$$dir/$$name-$$o.o; \
				$(CORPUS_CC) --target=$$triple -$$o -fno-asynchronous-unwind-tables -c $$src -o $$obj || exit 1; \
				$(OBJDUMP) -d --triple=$$triple --no-print-imm-hex --x86-asm-syntax=intel $$obj > $${obj%.o}.objdump || exit 1; \
			done; \
		done; \
	done

# Hand-written instruction lists that stress decoding paths compilers rarely
# emit (prefixes, VEX, x87, segment overrides): asm/<target>.s becomes
# <target>/stress-asm.o.
CORPUS_ASM := x86-64:x86_64-none-elf x86:i386-none-elf

.PHONY: corpus-asm
corpus-asm:
	@for t in $(CORPUS_ASM); do \
		dir=testdata/synthetic/$${t%%:*}; triple=$${t#*:}; mkdir -p $$dir; \
		$(CORPUS_CC) --target=$$triple -c testdata/synthetic/asm/$${t%%:*}.s -o $$dir/stress-asm.o || exit 1; \
		$(OBJDUMP) -d --triple=$$triple --no-print-imm-hex --x86-asm-syntax=intel $$dir/stress-asm.o > $$dir/stress-asm.objdump || exit 1; \
	done

# Native reference results for the IR interpreter test: harness.c calls
# every corpus function on seeded random inputs, compiled for the host
# with printf and memcpy intercepted, and records what the host computes.
VECTORS_DIR := $(or $(TMPDIR),/tmp)/anydec-vectors

vectors:
	@rm -rf $(VECTORS_DIR) && mkdir -p $(VECTORS_DIR)
	@for src in testdata/synthetic/src/*.c; do \
		$(CORPUS_CC) -O0 -fwrapv -ffp-contract=off -Dprintf=h_printf -Dmemcpy=h_memcpy -w \
			-c $$src -o $(VECTORS_DIR)/$$(basename $$src .c).o || exit 1; \
	done
	$(CORPUS_CC) -O0 -Wall -Wextra -c testdata/synthetic/harness/harness.c -o $(VECTORS_DIR)/harness.o
	$(CORPUS_CC) $(VECTORS_DIR)/*.o -o $(VECTORS_DIR)/harness
	$(VECTORS_DIR)/harness > testdata/synthetic/vectors.jsonl
