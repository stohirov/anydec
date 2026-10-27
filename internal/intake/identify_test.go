package intake

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

func TestIdentifyKind(t *testing.T) {
	ext4 := make([]byte, 0x500)
	ext4[0x438], ext4[0x439] = 0x53, 0xef

	tests := []struct {
		name string
		data []byte
		want Kind
	}{
		{"elf", []byte("\x7fELF\x02\x01\x01"), KindELF},
		{"pe", []byte("MZ\x90\x00"), KindPE},
		{"uimage", []byte{0x27, 0x05, 0x19, 0x56, 0, 0}, KindUImage},
		{"android boot", []byte("ANDROID!...."), KindAndroid},
		{"squashfs le", []byte("hsqs\x00\x00"), KindSquashFS},
		{"gzip", []byte{0x1f, 0x8b, 0x08}, KindGzip},
		{"xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, KindXZ},
		{"zstd", []byte{0x28, 0xb5, 0x2f, 0xfd}, KindZstd},
		{"apk", []byte("PK\x03\x04rest"), KindZip},
		{"ext4 superblock", ext4, KindExt4},
		{"intel hex", []byte(":10010000214601360121470136007EFE09D2190140\r\n"), KindIHex},
		{"s-record", []byte("S00F000068656C6C6F202020202000003C\n"), KindSRec},
		{"plain text", []byte("hello world"), KindUnknown},
		{"empty", nil, KindUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Identify(tt.data).Kind; got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestEntropyBounds(t *testing.T) {
	if e := Entropy(bytes.Repeat([]byte{0xff}, BlockSize)); e != 0 {
		t.Errorf("constant block: got %v, want 0", e)
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if e := Entropy(all); e != 8 {
		t.Errorf("uniform bytes: got %v, want 8", e)
	}
}

func TestIdentifyFlagsHighEntropyBlocks(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	random := make([]byte, BlockSize)
	for i := range random {
		random[i] = byte(rng.Uint32())
	}
	data := append(bytes.Repeat([]byte{0}, BlockSize), random...)
	data = append(data, 'x') // trailing partial block

	r := Identify(data)
	if len(r.Entropy) != 3 {
		t.Fatalf("got %d blocks, want 3", len(r.Entropy))
	}
	if len(r.HighEntropyBlocks) != 1 || r.HighEntropyBlocks[0] != 1 {
		t.Errorf("high-entropy blocks = %v, want [1]", r.HighEntropyBlocks)
	}
}
