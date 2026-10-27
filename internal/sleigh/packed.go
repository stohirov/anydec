package sleigh

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"
)

// A .sla file is the header "sla" plus a version byte, then a zlib stream
// holding Ghidra's packed encoding: a tree of elements, each with typed
// attributes. Every byte of the encoding is non-zero:
//
//	01xiiiii  element start      x=1: one more byte 1iiiiiii extends the id
//	10xiiiii  element end
//	11xiiiii  attribute, then a type byte ttttllll and l bytes of 7-bit data
//
// parsePacked turns the stream into an element tree; decode.go interprets it.

const (
	headerMask     = 0xc0
	elementStart   = 0x40
	elementEnd     = 0x80
	attributeStart = 0xc0
	extendMask     = 0x20
	idMask         = 0x1f
)

// Attribute type codes.
const (
	typeBool         = 1
	typeSignedPos    = 2
	typeSignedNeg    = 3
	typeUnsigned     = 4
	typeSpace        = 5
	typeSpecialSpace = 6
	typeString       = 7
)

// maxDepth bounds element nesting, so a corrupt file cannot recurse without
// limit. Real specs nest a few dozen levels deep.
const maxNesting = 512

type attr struct {
	id  uint32
	typ uint8
	val uint64 // integer magnitude, bool (0/1), space index or special code
	str string
}

type element struct {
	id    uint32
	attrs []attr
	kids  []*element
}

// errDecode wraps every failure to interpret a .sla file.
var errDecode = errors.New("sleigh: bad .sla file")

// decodeError is panicked by the element accessors and recovered at the
// decoding entry point, which keeps the interpreter in decode.go linear.
type decodeError struct{ msg string }

func fail(format string, args ...any) {
	panic(decodeError{fmt.Sprintf(format, args...)})
}

// readSLA decompresses and parses a whole .sla file.
func readSLA(data []byte) (*element, error) {
	if len(data) < 4 || string(data[:3]) != "sla" {
		return nil, fmt.Errorf("%w: missing header", errDecode)
	}
	if data[3] != slaVersion {
		return nil, fmt.Errorf("%w: format version %d, want %d", errDecode, data[3], slaVersion)
	}
	zr, err := zlib.NewReader(bytes.NewReader(data[4:]))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDecode, err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDecode, err)
	}
	return parsePacked(raw)
}

func parsePacked(raw []byte) (root *element, err error) {
	defer func() {
		if r := recover(); r != nil {
			de, ok := r.(decodeError)
			if !ok {
				panic(r)
			}
			err = fmt.Errorf("%w: %s", errDecode, de.msg)
		}
	}()
	p := packedReader{buf: raw}
	root = p.element(0)
	if p.pos != len(p.buf) {
		fail("%d trailing bytes after root element", len(p.buf)-p.pos)
	}
	return root, nil
}

type packedReader struct {
	buf []byte
	pos int
}

func (p *packedReader) next() byte {
	if p.pos >= len(p.buf) {
		fail("unexpected end of stream")
	}
	b := p.buf[p.pos]
	p.pos++
	return b
}

func (p *packedReader) peek() byte {
	if p.pos >= len(p.buf) {
		return 0
	}
	return p.buf[p.pos]
}

// header reads a record header byte and its optional extension byte.
func (p *packedReader) header() (kind byte, id uint32) {
	h := p.next()
	id = uint32(h & idMask)
	if h&extendMask != 0 {
		id = id<<7 | uint32(p.next()&0x7f)
	}
	return h & headerMask, id
}

func (p *packedReader) integer(n int) uint64 {
	if n > 10 {
		fail("integer of %d bytes", n)
	}
	var v uint64
	for ; n > 0; n-- {
		v = v<<7 | uint64(p.next()&0x7f)
	}
	return v
}

func (p *packedReader) element(depth int) *element {
	if depth > maxNesting {
		fail("elements nested deeper than %d", maxNesting)
	}
	kind, id := p.header()
	if kind != elementStart {
		fail("expected element start at offset %d", p.pos-1)
	}
	e := &element{id: id}
	for p.peek()&headerMask == attributeStart {
		_, aid := p.header()
		t := p.next()
		a := attr{id: aid, typ: t >> 4}
		n := int(t & 0xf)
		switch a.typ {
		case typeBool, typeSpecialSpace:
			a.val = uint64(n)
		case typeSignedPos, typeSignedNeg, typeUnsigned, typeSpace:
			a.val = p.integer(n)
		case typeString:
			size := p.integer(n)
			if size > uint64(len(p.buf)-p.pos) {
				fail("string runs past end of stream")
			}
			a.str = string(p.buf[p.pos : p.pos+int(size)])
			p.pos += int(size)
		default:
			fail("unknown attribute type %d", a.typ)
		}
		e.attrs = append(e.attrs, a)
	}
	for p.peek()&headerMask == elementStart {
		e.kids = append(e.kids, p.element(depth+1))
	}
	kind, endID := p.header()
	if kind != elementEnd || endID != id {
		fail("element %s not closed", elemName(id))
	}
	return e
}

func elemName(id uint32) string {
	if n, ok := elemNames[id]; ok {
		return n
	}
	return fmt.Sprintf("element(%d)", id)
}

func attrName(id uint32) string {
	if n, ok := attrNames[id]; ok {
		return n
	}
	return fmt.Sprintf("attr(%d)", id)
}

// Accessors. Each panics with a decodeError when the attribute is missing or
// has the wrong type; decoding recovers it into an error.

func (e *element) find(id uint32) *attr {
	for i := range e.attrs {
		if e.attrs[i].id == id {
			return &e.attrs[i]
		}
	}
	return nil
}

func (e *element) has(id uint32) bool { return e.find(id) != nil }

func (e *element) must(id uint32) *attr {
	a := e.find(id)
	if a == nil {
		fail("<%s> has no %s attribute", elemName(e.id), attrName(id))
	}
	return a
}

func (e *element) int(id uint32) int64 {
	a := e.must(id)
	switch a.typ {
	case typeSignedPos:
		return int64(a.val)
	case typeSignedNeg:
		return -int64(a.val)
	}
	fail("<%s> %s is not a signed integer", elemName(e.id), attrName(id))
	return 0
}

func (e *element) uint(id uint32) uint64 {
	a := e.must(id)
	if a.typ != typeUnsigned {
		fail("<%s> %s is not an unsigned integer", elemName(e.id), attrName(id))
	}
	return a.val
}

func (e *element) bool(id uint32) bool {
	a := e.must(id)
	if a.typ != typeBool {
		fail("<%s> %s is not a boolean", elemName(e.id), attrName(id))
	}
	return a.val != 0
}

// boolOr returns a boolean attribute, or def when it is absent.
func (e *element) boolOr(id uint32, def bool) bool {
	if !e.has(id) {
		return def
	}
	return e.bool(id)
}

func (e *element) str(id uint32) string {
	a := e.must(id)
	if a.typ != typeString {
		fail("<%s> %s is not a string", elemName(e.id), attrName(id))
	}
	return a.str
}

// space returns the index of the address space an attribute names.
func (e *element) space(id uint32) int {
	a := e.must(id)
	if a.typ != typeSpace {
		fail("<%s> %s is not an address space", elemName(e.id), attrName(id))
	}
	return int(a.val)
}

func (e *element) expect(id uint32) {
	if e.id != id {
		fail("expected <%s>, got <%s>", elemName(id), elemName(e.id))
	}
}

// child returns the i-th child, which must exist.
func (e *element) child(i int) *element {
	if i >= len(e.kids) {
		fail("<%s> has %d children, want at least %d", elemName(e.id), len(e.kids), i+1)
	}
	return e.kids[i]
}

// dump writes the tree in an XML-like form, for debugging specs.
func (e *element) dump(w io.Writer, depth int) {
	indent := strings.Repeat("  ", depth)
	fmt.Fprintf(w, "%s<%s", indent, elemName(e.id))
	for _, a := range e.attrs {
		fmt.Fprintf(w, " %s=", attrName(a.id))
		switch a.typ {
		case typeBool:
			fmt.Fprint(w, a.val != 0)
		case typeSignedNeg:
			fmt.Fprintf(w, "-%d", a.val)
		case typeSignedPos:
			fmt.Fprint(w, a.val)
		case typeUnsigned:
			fmt.Fprintf(w, "%#x", a.val)
		case typeSpace:
			fmt.Fprintf(w, "space#%d", a.val)
		case typeSpecialSpace:
			fmt.Fprintf(w, "special#%d", a.val)
		case typeString:
			fmt.Fprintf(w, "%q", a.str)
		}
	}
	if len(e.kids) == 0 {
		fmt.Fprintln(w, "/>")
		return
	}
	fmt.Fprintln(w, ">")
	for _, k := range e.kids {
		k.dump(w, depth+1)
	}
	fmt.Fprintf(w, "%s</%s>\n", indent, elemName(e.id))
}
