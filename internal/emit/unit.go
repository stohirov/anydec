package emit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/stohirov/decompile-anything/internal/loader"
	"github.com/stohirov/decompile-anything/internal/ssa"
)

// Unit renders functions of one program as a C translation unit: helper
// functions the code needs, the program's data the code references,
// declarations of every function and import, then the bodies. The result
// compiles for the program's own target.
type Unit struct {
	Prog  *loader.Program
	Img   ssa.Image
	Funcs []*ssa.Func // every function, for prototypes and call targets
	// Addresses adds each statement's instruction address as a comment.
	Addresses bool

	byEntry  map[uint64]*ssa.Func
	helpers  map[string]string // name -> definition
	segments map[string]bool   // segments emitted as arrays
	objects  map[string]bool   // object symbols emitted
	imports  map[string]*importUse
}

type importUse struct {
	ret     string // C return type, "" until a call site says
	proto   string // parameter list when every call site agrees and passes floats
	sites   map[string]bool
	data    bool // referenced as data, not called
	callers int
}

func (u *Unit) init() {
	if u.byEntry != nil {
		return
	}
	u.byEntry = map[uint64]*ssa.Func{}
	for _, f := range u.Funcs {
		u.byEntry[f.Entry] = f
	}
	u.helpers = map[string]string{}
	u.segments = map[string]bool{}
	u.objects = map[string]bool{}
	u.imports = map[string]*importUse{}
}

// Function renders one function's definition alone.
func (u *Unit) Function(f *ssa.Func) string {
	u.init()
	return newFuncEmitter(u, f).emit()
}

// Source renders a complete translation unit holding fns.
func (u *Unit) Source(fns []*ssa.Func) string {
	u.init()
	var bodies []string
	for _, f := range fns {
		bodies = append(bodies, newFuncEmitter(u, f).emit())
	}
	var sb strings.Builder
	sb.WriteString("/* Decompiled by anydec. */\n#include <stdint.h>\n\n")
	if len(u.helpers) > 0 {
		names := sortedKeys(u.helpers)
		for _, n := range names {
			sb.WriteString(u.helpers[n])
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}
	if g := u.globals(); g != "" {
		sb.WriteString(g)
		sb.WriteString("\n")
	}
	for _, n := range sortedKeys(u.imports) {
		im := u.imports[n]
		switch {
		case im.data && im.callers == 0:
			fmt.Fprintf(&sb, "extern uint8_t %s[];\n", n)
		default:
			ret := im.ret
			if ret == "" {
				ret = "void"
			}
			fmt.Fprintf(&sb, "extern %s %s(%s);\n", ret, n, im.proto)
		}
	}
	for _, f := range u.Funcs {
		fmt.Fprintf(&sb, "%s;\n", u.signature(f))
	}
	sb.WriteString("\n")
	for _, b := range bodies {
		sb.WriteString(b)
		sb.WriteString("\n")
	}
	return sb.String()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ident makes a name usable as a C identifier.
func ident(name string) string {
	var b strings.Builder
	for i, r := range name {
		switch {
		case r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

func (u *Unit) ptrSize() int {
	if len(u.Funcs) > 0 && u.Funcs[0].Arch != nil && u.Funcs[0].Arch.PointerSize > 0 {
		return u.Funcs[0].Arch.PointerSize
	}
	return 4
}

// intType names the unsigned C type of a size-byte integer.
func intType(size int) string {
	switch {
	case size <= 1:
		return "uint8_t"
	case size <= 2:
		return "uint16_t"
	case size <= 4:
		return "uint32_t"
	}
	return "uint64_t"
}

func sintType(size int) string { return "int" + strings.TrimPrefix(intType(size), "uint") }

func floatType(size int) string {
	if size == 4 {
		return "float"
	}
	return "double"
}

// retType is the C return type of a prototype.
func retType(p *ssa.Proto) string {
	if p == nil || len(p.Returns) == 0 {
		return "void"
	}
	if len(p.Returns) == 1 && p.Returns[0].Float && (p.Returns[0].Size == 4 || p.Returns[0].Size == 8) {
		return floatType(p.Returns[0].Size)
	}
	return intType(p.RetSize())
}

func paramType(p ssa.Param) string {
	if p.Float && (p.Size == 4 || p.Size == 8) {
		return floatType(p.Size)
	}
	return intType(p.Size)
}

// Signature is f's C declarator, with parameter names.
func (u *Unit) Signature(f *ssa.Func) string { return u.signature(f) }

func (u *Unit) signature(f *ssa.Func) string {
	var ps []string
	if f.Proto != nil {
		for i, p := range f.Proto.Params {
			ps = append(ps, fmt.Sprintf("%s a%d", paramType(p), i+1))
		}
	}
	if len(ps) == 0 {
		ps = []string{"void"}
	}
	return fmt.Sprintf("%s %s(%s)", retType(f.Proto), ident(f.Name), strings.Join(ps, ", "))
}

// helper registers a helper function's definition and returns its name.
func (u *Unit) helper(name, def string) string {
	u.helpers[name] = def
	return name
}

// addr renders an address constant as a reference to what it points at:
// a function, an import, a string literal, a data object or a segment.
// It returns false when x is not inside the program.
func (u *Unit) addr(x uint64, size int) (string, bool) {
	p := u.Prog
	cast := "(" + intType(size) + ")"
	for _, cand := range []uint64{x, x &^ 1} {
		if f := u.byEntry[cand]; f != nil && (cand == x || p.ModeAt(cand) == loader.ModeThumb) {
			return cast + ident(f.Name), true
		}
	}
	if s, ok := p.Import(x); ok {
		im := u.importUse(s.Name)
		im.data = true
		return cast + ident(s.Name), true
	}
	seg := p.Segment(x)
	if seg == nil || seg.Name == loader.ExternalSegment {
		return "", false
	}
	if seg.Perm&loader.PermW == 0 {
		if str, ok := cString(seg.Data[x-seg.Addr:]); ok {
			return cast + strconv.Quote(str), true
		}
	}
	for i := len(p.Symbols) - 1; i >= 0; i-- {
		s := p.Symbols[i]
		if s.Kind == loader.SymObject && s.Addr <= x && x < s.Addr+max(s.Size, 1) && p.Segment(s.Addr) == seg {
			u.objects[s.Name] = true
			return offsetExpr(cast+ident(s.Name), x-s.Addr), true
		}
	}
	u.segments[seg.Name] = true
	return offsetExpr(cast+segIdent(seg.Name), x-seg.Addr), true
}

func segName(p *loader.Program, addr uint64) string {
	if s := p.Segment(addr); s != nil {
		return s.Name
	}
	return ""
}

// ptr renders an address inside a data object or segment as a byte
// pointer expression, without converting it to an integer.
func (u *Unit) ptr(x uint64) (string, bool) {
	s, ok := u.addr(x, u.ptrSize())
	if !ok {
		return "", false
	}
	cast := "(" + intType(u.ptrSize()) + ")"
	if !strings.HasPrefix(s, cast) && !strings.HasPrefix(s, "("+cast) {
		return "", false
	}
	s = strings.Replace(s, cast, "", 1)
	if strings.HasPrefix(s, "\"") {
		return "", false
	}
	return s, true
}

func offsetExpr(base string, off uint64) string {
	if off == 0 {
		return base
	}
	return fmt.Sprintf("(%s + %#x)", base, off)
}

func segIdent(name string) string { return "seg" + ident(name) }

// cString returns the NUL-terminated printable string at the start of b.
func cString(b []byte) (string, bool) {
	for i, c := range b {
		if c == 0 {
			if i == 0 {
				return "", false
			}
			return string(b[:i]), true
		}
		if (c < 0x20 || c > 0x7e) && c != '\n' && c != '\t' && c != '\r' {
			return "", false
		}
		if i > 4096 {
			break
		}
	}
	return "", false
}

func (u *Unit) importUse(name string) *importUse {
	im := u.imports[name]
	if im == nil {
		im = &importUse{sites: map[string]bool{}}
		u.imports[name] = im
	}
	return im
}

// globals defines the data the emitted code references: whole segments
// where code points between named objects, otherwise each object.
func (u *Unit) globals() string {
	p := u.Prog
	var sb strings.Builder
	defined := map[string]bool{}
	for _, seg := range p.Segments {
		if !u.segments[seg.Name] {
			continue
		}
		fmt.Fprintf(&sb, "%s;\n", array(segIdent(seg.Name), seg.Data, seg.Perm&loader.PermW == 0, "static "))
		for _, s := range p.Symbols {
			if s.Kind == loader.SymObject && u.objects[s.Name] && segName(p, s.Addr) == seg.Name {
				fmt.Fprintf(&sb, "#define %s (%s + %#x)\n", ident(s.Name), segIdent(seg.Name), s.Addr-seg.Addr)
				defined[s.Name] = true
			}
		}
	}
	for _, s := range p.Symbols {
		if s.Kind != loader.SymObject || !u.objects[s.Name] || defined[s.Name] {
			continue
		}
		defined[s.Name] = true
		seg := p.Segment(s.Addr)
		data := make([]byte, max(s.Size, 1))
		if seg != nil {
			copy(data, seg.Data[s.Addr-seg.Addr:])
		}
		fmt.Fprintf(&sb, "%s;\n", array(ident(s.Name), data, seg != nil && seg.Perm&loader.PermW == 0, ""))
	}
	return sb.String()
}

// array defines a byte array holding data.
func array(name string, data []byte, readOnly bool, storage string) string {
	var sb strings.Builder
	sb.WriteString(storage)
	if readOnly {
		sb.WriteString("const ")
	}
	fmt.Fprintf(&sb, "uint8_t %s[%d] __attribute__((aligned(16)))", name, max(len(data), 1))
	zero := true
	for _, c := range data {
		zero = zero && c == 0
	}
	if zero {
		return sb.String()
	}
	sb.WriteString(" = {")
	for i, c := range data {
		if i%16 == 0 {
			sb.WriteString("\n    ")
		}
		fmt.Fprintf(&sb, "%#02x,", c)
	}
	sb.WriteString("\n}")
	return sb.String()
}

// callee names a direct call target.
func (u *Unit) callee(target uint64) (name string, f *ssa.Func, imp bool) {
	if f := u.byEntry[target]; f != nil {
		return ident(f.Name), f, false
	}
	if s, ok := u.Prog.Import(target); ok {
		return ident(s.Name), nil, true
	}
	if s, ok := u.Prog.Symbol(target); ok {
		return ident(s.Name), nil, true
	}
	return "", nil, false
}

// archIs reports whether f's processor is proc.
func archIs(f *ssa.Func, proc string) bool {
	return f.Arch != nil && strings.HasPrefix(f.Arch.Language, proc+":")
}
