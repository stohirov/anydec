VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/stohirov/decompile-anything/engine.Version=$(VERSION)

.PHONY: build test vet fmt check clean corpus

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
CORPUS_TARGETS := arm:armv7a-none-eabi thumb:thumbv7m-none-eabi thumb-hf:thumbv7em-none-eabihf
CORPUS_OPTS := O0 O2 Os

corpus:
	@for t in $(CORPUS_TARGETS); do \
		dir=testdata/synthetic/$${t%%:*}; triple=$${t#*:}; mkdir -p $$dir; \
		for src in testdata/synthetic/src/*.c; do \
			name=$$(basename $$src .c); \
			for o in $(CORPUS_OPTS); do \
				obj=$$dir/$$name-$$o.o; \
				$(CORPUS_CC) --target=$$triple -$$o -fno-asynchronous-unwind-tables -c $$src -o $$obj || exit 1; \
				$(OBJDUMP) -d --triple=$$triple --no-print-imm-hex $$obj > $${obj%.o}.objdump || exit 1; \
			done; \
		done; \
	done
