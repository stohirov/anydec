package analysis

import (
	"slices"
	"testing"

	"github.com/stohirov/decompile-anything/internal/ir"
)

type fakePass struct {
	name            string
	needs, provides []Fact
}

func (p fakePass) Name() string              { return p.name }
func (p fakePass) Needs() []Fact             { return p.needs }
func (p fakePass) Provides() []Fact          { return p.provides }
func (p fakePass) Run(fn *ir.Function) error { return nil }

func names(ps []Pass) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Name())
	}
	return out
}

func TestOrderRespectsDependencies(t *testing.T) {
	passes := []Pass{
		fakePass{"stack", []Fact{"ssa"}, []Fact{"stack"}},
		fakePass{"ssa", []Fact{"cfg"}, []Fact{"ssa"}},
		fakePass{"cfg", nil, []Fact{"cfg"}},
		fakePass{"consts", []Fact{"ssa"}, nil},
	}
	got, err := Order(passes)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cfg", "ssa", "stack", "consts"}
	if !slices.Equal(names(got), want) {
		t.Errorf("got %v, want %v", names(got), want)
	}
}

func TestOrderErrors(t *testing.T) {
	tests := map[string][]Pass{
		"missing provider": {fakePass{"ssa", []Fact{"cfg"}, []Fact{"ssa"}}},
		"cycle": {
			fakePass{"a", []Fact{"b"}, []Fact{"a"}},
			fakePass{"b", []Fact{"a"}, []Fact{"b"}},
		},
		"duplicate provider": {
			fakePass{"a", nil, []Fact{"cfg"}},
			fakePass{"b", nil, []Fact{"cfg"}},
		},
	}
	for name, passes := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Order(passes); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
