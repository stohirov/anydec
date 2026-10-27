// Package abi models calling conventions, read from Ghidra compiler specs
// (.cspec): which registers carry parameters and results, which survive a
// call, where stack parameters start, and how much the callee pops.
package abi

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/fs"
	"strconv"
)

// Convention is one prototype model of a compiler spec.
type Convention struct {
	Name string
	// IntParams and FloatParams list parameter registers in the order
	// arguments fill them.
	IntParams   []string
	FloatParams []string
	// StackParams is set when arguments overflow onto the stack, starting
	// StackOffset bytes above the stack pointer at entry, in slots of
	// StackAlign bytes.
	StackParams bool
	StackOffset int64
	StackAlign  int
	IntReturns  []string
	// FloatReturns hold floating-point results.
	FloatReturns []string
	// Unaffected registers keep their values across a call; every other
	// register is undefined after one.
	Unaffected   []string
	StackPointer string
	// ExtraPop is how far the stack pointer moves over a call beyond what
	// the caller's own code does: the return address an x86 callee pops.
	ExtraPop int64
}

type cspec struct {
	StackPointer struct {
		Register string `xml:"register,attr"`
	} `xml:"stackpointer"`
	Default struct {
		Proto prototype `xml:"prototype"`
	} `xml:"default_proto"`
	Protos []prototype `xml:"prototype"`
}

type prototype struct {
	Name       string  `xml:"name,attr"`
	ExtraPop   string  `xml:"extrapop,attr"`
	Input      []entry `xml:"input>pentry"`
	Output     []entry `xml:"output>pentry"`
	Unaffected []struct {
		Name string `xml:"name,attr"`
	} `xml:"unaffected>register"`
}

type entry struct {
	MaxSize  int    `xml:"maxsize,attr"`
	Align    int    `xml:"align,attr"`
	Metatype string `xml:"metatype,attr"`
	Storage  string `xml:"storage,attr"`
	Register *struct {
		Name string `xml:"name,attr"`
	} `xml:"register"`
	Addr *struct {
		Offset string `xml:"offset,attr"`
		Space  string `xml:"space,attr"`
	} `xml:"addr"`
}

// Load reads the prototype named proto from the compiler spec at path in
// fsys; an empty proto selects the spec's default.
func Load(fsys fs.FS, path, proto string) (*Convention, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, err
	}
	var spec cspec
	if err := xml.Unmarshal(stripProlog(data), &spec); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p := &spec.Default.Proto
	if proto != "" && proto != p.Name {
		p = nil
		for i := range spec.Protos {
			if spec.Protos[i].Name == proto {
				p = &spec.Protos[i]
			}
		}
		if p == nil {
			return nil, fmt.Errorf("%s: no prototype %q", path, proto)
		}
	}
	c := &Convention{Name: p.Name, StackPointer: spec.StackPointer.Register}
	if p.ExtraPop != "" && p.ExtraPop != "unknown" {
		if c.ExtraPop, err = strconv.ParseInt(p.ExtraPop, 0, 64); err != nil {
			return nil, fmt.Errorf("%s: extrapop: %w", path, err)
		}
	}
	for _, e := range p.Input {
		switch {
		case e.Storage == "hiddenret":
		case e.Register != nil && e.float():
			c.FloatParams = append(c.FloatParams, e.Register.Name)
		case e.Register != nil:
			c.IntParams = append(c.IntParams, e.Register.Name)
		case e.Addr != nil && e.Addr.Space == "stack":
			if c.StackOffset, err = strconv.ParseInt(e.Addr.Offset, 0, 64); err != nil {
				return nil, fmt.Errorf("%s: stack offset: %w", path, err)
			}
			c.StackParams, c.StackAlign = true, max(e.Align, 1)
		}
	}
	for _, e := range p.Output {
		switch {
		case e.Register != nil && e.float():
			c.FloatReturns = append(c.FloatReturns, e.Register.Name)
		case e.Register != nil:
			c.IntReturns = append(c.IntReturns, e.Register.Name)
		}
	}
	for _, r := range p.Unaffected {
		c.Unaffected = append(c.Unaffected, r.Name)
	}
	if c.StackPointer == "" {
		return nil, fmt.Errorf("%s: no stack pointer", path)
	}
	return c, nil
}

func (e entry) float() bool { return e.Metatype == "float" || e.Storage == "float" }

// stripProlog drops a leading <?xml ...?> declaration, which encoding/xml
// rejects when it declares XML 1.1.
func stripProlog(data []byte) []byte {
	trimmed := bytes.TrimLeft(data, " \t\r\n\ufeff")
	if bytes.HasPrefix(trimmed, []byte("<?xml")) {
		if i := bytes.Index(trimmed, []byte("?>")); i >= 0 {
			return trimmed[i+2:]
		}
	}
	return data
}
