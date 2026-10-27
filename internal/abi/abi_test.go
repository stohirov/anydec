package abi

import (
	"slices"
	"testing"

	"github.com/stohirov/decompile-anything/third_party/ghidra"
)

func TestLoadVendoredSpecs(t *testing.T) {
	tests := []struct {
		path, proto string
		check       func(t *testing.T, c *Convention)
	}{
		{"ARM/data/languages/ARM.cspec", "", func(t *testing.T, c *Convention) {
			if !slices.Equal(c.IntParams, []string{"r0", "r1", "r2", "r3"}) || len(c.FloatParams) != 16 {
				t.Errorf("params %v %v", c.IntParams, c.FloatParams)
			}
			if !c.StackParams || c.StackOffset != 0 || c.StackAlign != 4 || c.ExtraPop != 0 {
				t.Errorf("stack %v %d %d pop %d", c.StackParams, c.StackOffset, c.StackAlign, c.ExtraPop)
			}
			if !slices.Equal(c.IntReturns, []string{"r0", "r1"}) || c.FloatReturns[0] != "s0" {
				t.Errorf("returns %v %v", c.IntReturns, c.FloatReturns)
			}
			if !slices.Contains(c.Unaffected, "r4") || slices.Contains(c.Unaffected, "r0") || c.StackPointer != "sp" {
				t.Errorf("unaffected %v, sp %q", c.Unaffected, c.StackPointer)
			}
		}},
		{"ARM/data/languages/ARM.cspec", "__stdcall_softfp", func(t *testing.T, c *Convention) {
			if len(c.FloatParams) != 0 || len(c.FloatReturns) != 0 || len(c.IntParams) != 4 {
				t.Errorf("soft-float params %v %v", c.IntParams, c.FloatParams)
			}
		}},
		{"x86/data/languages/x86-64-gcc.cspec", "", func(t *testing.T, c *Convention) {
			if !slices.Equal(c.IntParams, []string{"RDI", "RSI", "RDX", "RCX", "R8", "R9"}) || c.FloatParams[0] != "XMM0_Qa" {
				t.Errorf("params %v %v", c.IntParams, c.FloatParams)
			}
			if c.StackOffset != 8 || c.ExtraPop != 8 || c.StackPointer != "RSP" {
				t.Errorf("stack offset %d, pop %d, sp %q", c.StackOffset, c.ExtraPop, c.StackPointer)
			}
		}},
		{"AARCH64/data/languages/AARCH64.cspec", "", func(t *testing.T, c *Convention) {
			if c.IntParams[0] != "x0" || len(c.IntParams) != 8 || c.FloatParams[0] != "q0" {
				t.Errorf("params %v %v (x8 is the hidden return, not a parameter)", c.IntParams, c.FloatParams)
			}
		}},
	}
	for _, tt := range tests {
		c, err := Load(ghidra.Processors, "Processors/"+tt.path, tt.proto)
		if err != nil {
			t.Fatal(err)
		}
		tt.check(t, c)
	}
	if _, err := Load(ghidra.Processors, "Processors/ARM/data/languages/ARM.cspec", "nope"); err == nil {
		t.Error("unknown prototype loaded")
	}
}
