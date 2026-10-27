package sleigh

import (
	"math/rand/v2"
	"testing"
)

// Firmware is hostile input: any bytes must decode or fail with an error,
// never panic.

func decodeAll(t testing.TB, l *Language, code []byte, thumb bool) {
	d := l.NewDecoder(memBytes{0, code})
	if thumb {
		if err := d.SetContext("TMode", 0, 0, 1); err != nil {
			t.Fatal(err)
		}
	}
	step := uint64(4)
	if thumb {
		step = 2
	}
	for a := uint64(0); a+step <= uint64(len(code)); a += step {
		d.Decode(a)
		d.Translate(a)
	}
}

func TestRandomBytesNeverPanic(t *testing.T) {
	l := loadARM(t, "ARM:LE:32:v8")
	rng := rand.New(rand.NewPCG(7, 11))
	n := 1 << 16
	if testing.Short() {
		n = 1 << 12
	}
	code := make([]byte, n)
	for i := range code {
		code[i] = byte(rng.Uint32())
	}
	decodeAll(t, l, code, false)
	decodeAll(t, l, code, true)
}

func FuzzDecode(f *testing.F) {
	l, err := LoadLanguage(ghidraFS(), "ARM:LE:32:v8")
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{0x00, 0x00, 0x81, 0xe0}, false)
	f.Add([]byte{0x14, 0xbf, 0x90, 0xfb, 0xf1, 0xf0}, true)
	f.Fuzz(func(t *testing.T, code []byte, thumb bool) {
		decodeAll(t, l, code, thumb)
	})
}
