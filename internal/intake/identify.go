// Package intake turns whatever the user has (an update file, a flash dump,
// an APK) into a tree of typed artifacts, each with a known loader.
//
// Stage 1 (identify) classifies bytes, stage 2 (unpack) recursively extracts
// children, and executable leaves go to the loader package.
package intake

import (
	"bytes"
	"math"
)

// Kind is the classified type of an artifact.
type Kind string

const (
	KindUnknown  Kind = "unknown"
	KindELF      Kind = "elf"
	KindPE       Kind = "pe"
	KindMachO    Kind = "macho"
	KindUImage   Kind = "uimage"
	KindFIT      Kind = "fit"
	KindAndroid  Kind = "android-boot"
	KindSquashFS Kind = "squashfs"
	KindCramFS   Kind = "cramfs"
	KindJFFS2    Kind = "jffs2"
	KindUBI      Kind = "ubi"
	KindExt4     Kind = "ext4"
	KindGzip     Kind = "gzip"
	KindXZ       Kind = "xz"
	KindLZMA     Kind = "lzma"
	KindLZ4      Kind = "lz4"
	KindZstd     Kind = "zstd"
	KindZip      Kind = "zip" // APK and JAR are zip containers
	KindDEX      Kind = "dex"
	KindIHex     Kind = "ihex"
	KindSRec     Kind = "srec"
)

// BlockSize is the window used for entropy measurement.
const BlockSize = 4096

// HighEntropy is the bits-per-byte level above which a block is treated as
// compressed or encrypted.
const HighEntropy = 7.9

type magic struct {
	offset int
	bytes  []byte
	kind   Kind
}

// Ordered most specific first; Identify returns the first match.
var magics = []magic{
	{0, []byte("\x7fELF"), KindELF},
	{0, []byte("MZ"), KindPE},
	{0, []byte{0xfe, 0xed, 0xfa, 0xce}, KindMachO},
	{0, []byte{0xfe, 0xed, 0xfa, 0xcf}, KindMachO},
	{0, []byte{0xce, 0xfa, 0xed, 0xfe}, KindMachO},
	{0, []byte{0xcf, 0xfa, 0xed, 0xfe}, KindMachO},
	{0, []byte{0x27, 0x05, 0x19, 0x56}, KindUImage},
	{0, []byte{0xd0, 0x0d, 0xfe, 0xed}, KindFIT}, // flattened device tree
	{0, []byte("ANDROID!"), KindAndroid},
	{0, []byte("hsqs"), KindSquashFS},
	{0, []byte("sqsh"), KindSquashFS},
	{0, []byte{0x45, 0x3d, 0xcd, 0x28}, KindCramFS},
	{0, []byte{0x85, 0x19}, KindJFFS2},
	{0, []byte{0x19, 0x85}, KindJFFS2},
	{0, []byte("UBI#"), KindUBI},
	{0x438, []byte{0x53, 0xef}, KindExt4}, // superblock s_magic
	{0, []byte{0x1f, 0x8b}, KindGzip},
	{0, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, KindXZ},
	{0, []byte{0x5d, 0x00, 0x00}, KindLZMA},
	{0, []byte{0x04, 0x22, 0x4d, 0x18}, KindLZ4},
	{0, []byte{0x28, 0xb5, 0x2f, 0xfd}, KindZstd},
	{0, []byte("PK\x03\x04"), KindZip},
	{0, []byte("dex\n"), KindDEX},
}

// Report is the result of identifying one byte region.
type Report struct {
	Kind Kind
	// Entropy holds bits per byte for each BlockSize window, in order.
	Entropy []float64
	// HighEntropyBlocks indexes the windows at or above HighEntropy.
	HighEntropyBlocks []int
}

// Identify classifies data by magic bytes and measures per-block entropy.
func Identify(data []byte) Report {
	r := Report{Kind: classify(data)}
	for i := 0; i < len(data); i += BlockSize {
		end := min(i+BlockSize, len(data))
		e := Entropy(data[i:end])
		r.Entropy = append(r.Entropy, e)
		if e >= HighEntropy {
			r.HighEntropyBlocks = append(r.HighEntropyBlocks, len(r.Entropy)-1)
		}
	}
	return r
}

func classify(data []byte) Kind {
	for _, m := range magics {
		end := m.offset + len(m.bytes)
		if end <= len(data) && bytes.Equal(data[m.offset:end], m.bytes) {
			return m.kind
		}
	}
	switch {
	case isTextRecord(data, ':'):
		return KindIHex
	case isTextRecord(data, 'S') && len(data) > 1 && data[1] >= '0' && data[1] <= '9':
		return KindSRec
	}
	return KindUnknown
}

// isTextRecord reports whether data looks like a line-based hex record file
// whose lines start with lead.
func isTextRecord(data []byte, lead byte) bool {
	if len(data) == 0 || data[0] != lead {
		return false
	}
	line, _, _ := bytes.Cut(data, []byte("\n"))
	line = bytes.TrimRight(line, "\r")
	for _, c := range line[1:] {
		if !isHex(c) {
			return false
		}
	}
	return len(line) > 1
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// Entropy returns the Shannon entropy of b in bits per byte (0 to 8).
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
