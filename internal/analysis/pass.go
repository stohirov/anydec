// Package analysis holds the pass manager and the passes that find code:
// function discovery, CFG construction and jump-table resolution. Data-
// flow analysis on the result lives in package ssa.
package analysis

import (
	"fmt"
	"sort"

	"github.com/stohirov/decompile-anything/internal/ir"
)

// Fact names something a pass establishes about a function, such as "cfg"
// or "ssa". Passes declare the facts they need and the facts they produce.
type Fact string

// Pass is a transformation over one function's IR.
type Pass interface {
	Name() string
	Needs() []Fact
	Provides() []Fact
	Run(fn *ir.Function) error
}

// Order sorts passes so every pass runs after the passes providing what it
// needs. Ties keep registration order. It fails on a missing provider or a
// dependency cycle.
func Order(passes []Pass) ([]Pass, error) {
	provider := map[Fact]int{}
	for i, p := range passes {
		for _, f := range p.Provides() {
			if j, dup := provider[f]; dup {
				return nil, fmt.Errorf("fact %q provided by both %s and %s", f, passes[j].Name(), p.Name())
			}
			provider[f] = i
		}
	}

	deps := make([][]int, len(passes))
	indegree := make([]int, len(passes))
	for i, p := range passes {
		for _, f := range p.Needs() {
			j, ok := provider[f]
			if !ok {
				return nil, fmt.Errorf("pass %s needs %q, which no pass provides", p.Name(), f)
			}
			deps[j] = append(deps[j], i)
			indegree[i]++
		}
	}

	var ready, out []int
	for i := range passes {
		if indegree[i] == 0 {
			ready = append(ready, i)
		}
	}
	for len(ready) > 0 {
		sort.Ints(ready)
		i := ready[0]
		ready = ready[1:]
		out = append(out, i)
		for _, k := range deps[i] {
			if indegree[k]--; indegree[k] == 0 {
				ready = append(ready, k)
			}
		}
	}
	if len(out) != len(passes) {
		return nil, fmt.Errorf("dependency cycle among passes")
	}

	ordered := make([]Pass, len(out))
	for n, i := range out {
		ordered[n] = passes[i]
	}
	return ordered, nil
}
