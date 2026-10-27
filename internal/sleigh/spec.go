package sleigh

import (
	"fmt"
	"sort"
)

// SpaceKind classifies an address space.
type SpaceKind uint8

const (
	SpaceConstant  SpaceKind = iota
	SpaceProcessor           // ram, register and other spaces the processor defines
	SpaceUnique              // p-code temporaries
	SpaceOther               // the "OTHER" space for overlay and debug data
)

// Space is an address space declared by a spec.
type Space struct {
	Name      string
	Index     int
	Kind      SpaceKind
	Size      int // bytes in an address
	WordSize  int // bytes per addressable unit
	BigEndian bool
}

// wrap reduces off to the space's address range.
func (s *Space) wrap(off uint64) uint64 {
	if s.Size >= 8 || s.Size <= 0 {
		return off
	}
	return off & (1<<(8*s.Size) - 1)
}

// Register is a named varnode in the register space (or any fixed varnode a
// spec names).
type Register struct {
	Name   string
	Space  *Space
	Offset uint64
	Size   int
}

// ContextVar is a named bit range of the context register, such as ARM's
// TMode. Bits number from the most significant bit of the first context word.
type ContextVar struct {
	Name      string
	StartBit  int
	EndBit    int
	Flow      bool
	wordIndex int
	shift     int
	mask      uint32
}

// Spec is a compiled SLEIGH processor spec loaded from a .sla file.
type Spec struct {
	BigEndian bool
	Alignment int
	uniqBase  uint64
	uniqMask  uint64
	maxDelay  int

	Spaces       []*Space // indexed by Space.Index; Spaces[0] is the constant space
	DefaultSpace *Space   // where code lives
	constSpace   *Space
	uniqueSpace  *Space

	symbols   []symbol
	globals   map[string]symbol
	root      *subtableSym
	context   []*ContextVar
	ctxWords  int // number of 32-bit context words
	userOps   []string
	Registers []*Register // sorted by space, offset, then size descending
}

// Space returns the address space with the given name, or nil.
func (s *Spec) Space(name string) *Space {
	for _, sp := range s.Spaces {
		if sp != nil && sp.Name == name {
			return sp
		}
	}
	return nil
}

// ContextVar returns the context variable with the given name, or nil.
func (s *Spec) ContextVar(name string) *ContextVar {
	for _, v := range s.context {
		if v.Name == name {
			return v
		}
	}
	return nil
}

// UserOp returns the name of a CALLOTHER user-defined operation.
func (s *Spec) UserOp(index int) string {
	if index >= 0 && index < len(s.userOps) {
		return s.userOps[index]
	}
	return fmt.Sprintf("userop%d", index)
}

// Register returns the register with the given name, or nil.
func (s *Spec) Register(name string) *Register {
	for _, r := range s.Registers {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// RegisterName returns the name of the register varnode at exactly (space,
// offset, size), or "".
func (s *Spec) RegisterName(space *Space, offset uint64, size int) string {
	i := sort.Search(len(s.Registers), func(i int) bool {
		r := s.Registers[i]
		if r.Space.Index != space.Index {
			return r.Space.Index > space.Index
		}
		if r.Offset != offset {
			return r.Offset > offset
		}
		return r.Size <= size
	})
	if i < len(s.Registers) {
		r := s.Registers[i]
		if r.Space == space && r.Offset == offset && r.Size == size {
			return r.Name
		}
	}
	return ""
}

// LoadSpec decodes a compiled .sla file.
func LoadSpec(sla []byte) (*Spec, error) {
	root, err := readSLA(sla)
	if err != nil {
		return nil, err
	}
	return decodeSpec(root)
}

func decodeSpec(root *element) (spec *Spec, err error) {
	defer func() {
		if r := recover(); r != nil {
			de, ok := r.(decodeError)
			if !ok {
				panic(r)
			}
			spec, err = nil, fmt.Errorf("%w: %s", errDecode, de.msg)
		}
	}()
	root.expect(eSleigh)
	if v := root.int(aVersion); v != slaVersion {
		fail("format version %d, want %d", v, slaVersion)
	}
	s := &Spec{
		BigEndian: root.boolOr(aBigendian, false),
		Alignment: 1,
		globals:   map[string]symbol{},
	}
	if root.has(aAlign) {
		s.Alignment = int(root.int(aAlign))
	}
	if root.has(aUniqbase) {
		s.uniqBase = root.uint(aUniqbase)
	}
	if root.has(aUniqmask) {
		s.uniqMask = root.uint(aUniqmask)
	}
	if root.has(aMaxdelay) {
		s.maxDelay = int(root.uint(aMaxdelay))
	}

	// Children: <sourcefiles>, <spaces>, <symbol_table>.
	for _, k := range root.kids {
		switch k.id {
		case eSpaces:
			s.decodeSpaces(k)
		case eSymbolTable:
			d := &specDecoder{spec: s}
			d.decodeSymbols(k)
		}
	}
	if s.DefaultSpace == nil {
		fail("no <spaces> element")
	}
	insn, ok := s.globals["instruction"].(*subtableSym)
	if !ok {
		fail("no instruction table")
	}
	s.root = insn
	s.indexRegisters()
	return s, nil
}

func (s *Spec) decodeSpaces(e *element) {
	s.constSpace = &Space{Name: "const", Index: 0, Kind: SpaceConstant, Size: 8, WordSize: 1}
	s.Spaces = []*Space{s.constSpace}
	defName := e.str(aDefaultspace)
	for _, k := range e.kids {
		sp := &Space{WordSize: 1}
		if k.has(aName) {
			sp.Name = k.str(aName)
		}
		sp.Index = int(k.int(aIndex))
		if k.has(aSize) {
			sp.Size = int(k.int(aSize))
		}
		if k.has(aWordsize) {
			sp.WordSize = int(k.int(aWordsize))
		}
		sp.BigEndian = k.boolOr(aBigendian, false)
		switch k.id {
		case eSpaceUnique:
			sp.Kind = SpaceUnique
			if sp.Name == "" {
				sp.Name = "unique"
			}
			s.uniqueSpace = sp
		case eSpaceOther:
			sp.Kind = SpaceOther
			if sp.Name == "" {
				sp.Name = "OTHER"
			}
		default:
			sp.Kind = SpaceProcessor
		}
		if sp.Index <= 0 || sp.Index > 255 {
			fail("space %q has bad index %d", sp.Name, sp.Index)
		}
		for len(s.Spaces) <= sp.Index {
			s.Spaces = append(s.Spaces, nil)
		}
		if s.Spaces[sp.Index] != nil {
			fail("two spaces with index %d", sp.Index)
		}
		s.Spaces[sp.Index] = sp
	}
	s.DefaultSpace = s.Space(defName)
	if s.DefaultSpace == nil {
		fail("default space %q is not declared", defName)
	}
}

func (s *Spec) spaceAt(i int) *Space {
	if i < 0 || i >= len(s.Spaces) || s.Spaces[i] == nil {
		fail("reference to undeclared space %d", i)
	}
	return s.Spaces[i]
}

func (s *Spec) indexRegisters() {
	for _, sym := range s.symbols {
		if v, ok := sym.(*varnodeSym); ok && v.space != nil {
			s.Registers = append(s.Registers, &Register{Name: v.name, Space: v.space, Offset: v.offset, Size: v.size})
		}
	}
	sort.Slice(s.Registers, func(i, j int) bool {
		a, b := s.Registers[i], s.Registers[j]
		if a.Space.Index != b.Space.Index {
			return a.Space.Index < b.Space.Index
		}
		if a.Offset != b.Offset {
			return a.Offset < b.Offset
		}
		if a.Size != b.Size {
			return a.Size > b.Size
		}
		return a.Name < b.Name
	})
}

// specDecoder carries state while the symbol table is decoded: symbols are
// created as empty shells from their headers first, so bodies can refer to
// any symbol by id, and constructor references inside expressions are fixed
// up once every subtable is complete.
type specDecoder struct {
	spec   *Spec
	fixups []func()
}

const (
	maxScopes  = 0x100000
	maxSymbols = 0x1000000
)

func (d *specDecoder) decodeSymbols(e *element) {
	nscopes, nsyms := e.int(aScopesize), e.int(aSymbolsize)
	if nscopes < 0 || nscopes > maxScopes || nsyms < 0 || nsyms > maxSymbols {
		fail("bad symbol table size")
	}
	s := d.spec
	s.symbols = make([]symbol, nsyms)
	i := 0
	for ; i < len(e.kids) && e.kids[i].id == eScope; i++ {
	}
	headers := e.kids[i:]
	if len(headers) < int(nsyms) {
		fail("symbol table has %d headers, want %d", len(headers), nsyms)
	}
	for _, h := range headers[:nsyms] {
		sym := newSymbol(h.id)
		if sym == nil {
			fail("unknown symbol header <%s>", elemName(h.id))
		}
		b := sym.base()
		b.name = h.str(aName)
		id := h.uint(aId)
		if id >= uint64(nsyms) || s.symbols[id] != nil {
			fail("bad symbol id %d", id)
		}
		b.id = int(id)
		if h.uint(aScope) == 0 {
			s.globals[b.name] = sym
		}
		s.symbols[id] = sym
	}
	for _, body := range headers[nsyms:] {
		sym := d.symbol(body.uint(aId))
		sym.decode(d, body)
	}
	for _, f := range d.fixups {
		f()
	}
}

func (d *specDecoder) symbol(id uint64) symbol {
	if id >= uint64(len(d.spec.symbols)) || d.spec.symbols[id] == nil {
		fail("reference to undefined symbol %d", id)
	}
	return d.spec.symbols[id]
}

func (d *specDecoder) triple(id uint64) tripleSymbol {
	t, ok := d.symbol(id).(tripleSymbol)
	if !ok {
		fail("symbol %d cannot be used as an operand", id)
	}
	return t
}

func newSymbol(header uint32) symbol {
	switch header {
	case eUseropHead:
		return &userOpSym{}
	case eEpsilonSymHead:
		return &epsilonSym{}
	case eValueSymHead:
		return &valueSym{}
	case eValuemapSymHead:
		return &valueMapSym{}
	case eNameSymHead:
		return &nameSym{}
	case eVarnodeSymHead:
		return &varnodeSym{}
	case eContextSymHead:
		return &contextSym{}
	case eVarlistSymHead:
		return &varListSym{}
	case eOperandSymHead:
		return &operandSym{}
	case eStartSymHead:
		return &startSym{}
	case eEndSymHead:
		return &endSym{}
	case eNext2SymHead:
		return &next2Sym{}
	case eSubtableSymHead:
		return &subtableSym{}
	}
	return nil
}

// Symbol bodies.

func (u *userOpSym) decode(d *specDecoder, e *element) {
	u.index = int(e.int(aIndex))
	for len(d.spec.userOps) <= u.index {
		d.spec.userOps = append(d.spec.userOps, "")
	}
	d.spec.userOps[u.index] = u.name
}

func (*epsilonSym) decode(*specDecoder, *element) {}
func (*startSym) decode(*specDecoder, *element)   {}
func (*endSym) decode(*specDecoder, *element)     {}
func (*next2Sym) decode(*specDecoder, *element)   {}

func (v *valueSym) decode(d *specDecoder, e *element) {
	v.val = d.expr(e.child(0))
}

func (v *valueMapSym) decode(d *specDecoder, e *element) {
	v.val = d.expr(e.child(0))
	for _, k := range e.kids[1:] {
		v.table = append(v.table, k.int(aVal))
	}
}

func (n *nameSym) decode(d *specDecoder, e *element) {
	n.val = d.expr(e.child(0))
	for _, k := range e.kids[1:] {
		name := "\t" // marks an index with no name
		if k.has(aName) {
			name = k.str(aName)
		}
		if name == "_" {
			name = "\t"
		}
		n.names = append(n.names, name)
	}
}

func (v *varnodeSym) decode(d *specDecoder, e *element) {
	v.space = d.spec.spaceAt(e.space(aSpace))
	v.offset = e.uint(aOff)
	v.size = int(e.int(aSize))
}

func (c *contextSym) decode(d *specDecoder, e *element) {
	vn, ok := d.symbol(e.uint(aVarnode)).(*varnodeSym)
	if !ok {
		fail("context symbol %s has no varnode", c.name)
	}
	c.vn = vn
	c.low = int(e.int(aLow))
	c.high = int(e.int(aHigh))
	c.flow = e.boolOr(aFlow, false)
	c.val = d.expr(e.child(0))
	f, ok := c.val.(*contextField)
	if !ok {
		fail("context symbol %s is not a context field", c.name)
	}
	cv := &ContextVar{Name: c.name, StartBit: f.startBit, EndBit: f.endBit, Flow: c.flow}
	cv.wordIndex, cv.shift, cv.mask = maskWord(f.startBit, f.endBit)
	d.spec.context = append(d.spec.context, cv)
	if w := f.endBit/32 + 1; w > d.spec.ctxWords {
		d.spec.ctxWords = w
	}
}

// maskWord locates context bits [sbit, ebit] inside one 32-bit word.
func maskWord(sbit, ebit int) (num, shift int, mask uint32) {
	num = sbit / 32
	if num != ebit/32 {
		fail("context field spans two words")
	}
	sbit -= num * 32
	ebit -= num * 32
	shift = 32 - ebit - 1
	mask = (^uint32(0) >> (sbit + shift)) << shift
	return num, shift, mask
}

func (v *varListSym) decode(d *specDecoder, e *element) {
	v.val = d.expr(e.child(0))
	for _, k := range e.kids[1:] {
		if k.id == eVar {
			r, ok := d.symbol(k.uint(aId)).(*varnodeSym)
			if !ok {
				fail("varnode list %s names a non-varnode", v.name)
			}
			v.regs = append(v.regs, r)
		} else {
			v.regs = append(v.regs, nil)
		}
	}
}

func (o *operandSym) decode(d *specDecoder, e *element) {
	o.hand = int(e.int(aIndex))
	o.relOffset = int(e.int(aOff))
	o.offsetBase = int(e.int(aBase))
	o.minLength = int(e.int(aMinlen))
	if e.has(aSubsym) {
		o.triple = d.triple(e.uint(aSubsym))
	}
	o.codeAddr = e.boolOr(aCode, false)
	o.local = d.expr(e.child(0))
	if len(e.kids) > 1 {
		o.def = d.expr(e.kids[1])
	}
}

func (t *subtableSym) decode(d *specDecoder, e *element) {
	n := e.int(aNumct)
	if n < 0 || n > maxSymbols {
		fail("bad constructor count %d", n)
	}
	t.cts = make([]*constructor, 0, n)
	for _, k := range e.kids {
		switch k.id {
		case eConstructor:
			ct := &constructor{parent: t, id: len(t.cts)}
			t.cts = append(t.cts, ct)
			ct.decode(d, k)
		case eDecision:
			t.tree = d.decision(k, t)
		}
	}
	if t.tree == nil {
		fail("table %s has no decision tree", t.name)
	}
}

func (ct *constructor) decode(d *specDecoder, e *element) {
	ct.firstWhitespace = int(e.int(aFirst))
	ct.minLength = int(e.int(aLength))
	ct.line = int(e.int(aLine))
	for _, k := range e.kids {
		switch k.id {
		case eOper:
			op, ok := d.symbol(k.uint(aId)).(*operandSym)
			if !ok {
				fail("constructor operand is not an operand symbol")
			}
			ct.operands = append(ct.operands, op)
		case ePrint:
			ct.print = append(ct.print, printPiece{text: k.str(aPiece), operand: -1})
		case eOpprint:
			ct.print = append(ct.print, printPiece{operand: int(k.int(aId))})
		case eContextOp:
			op := &contextOp{num: int(k.int(aI)), shift: int(k.int(aShift)), mask: uint32(k.uint(aMask))}
			op.val = d.expr(k.child(0))
			ct.context = append(ct.context, op)
		case eCommit:
			ct.context = append(ct.context, &contextCommit{
				sym:  d.triple(k.uint(aId)),
				num:  int(k.int(aNumber)),
				mask: uint32(k.uint(aMask)),
				flow: k.bool(aFlow),
			})
		case eConstructTpl:
			tpl, section := d.constructTpl(k)
			if section < 0 {
				if ct.templ != nil {
					fail("constructor at line %d has two main sections", ct.line)
				}
				ct.templ = tpl
				continue
			}
			for len(ct.named) <= section {
				ct.named = append(ct.named, nil)
			}
			ct.named[section] = tpl
		default:
			fail("unexpected <%s> in constructor", elemName(k.id))
		}
	}
	for _, p := range ct.print {
		if p.operand >= len(ct.operands) {
			fail("constructor at line %d prints operand %d of %d", ct.line, p.operand, len(ct.operands))
		}
	}
	ct.flowThru = -1
	if len(ct.print) == 1 && ct.print[0].operand >= 0 {
		ct.flowThru = ct.print[0].operand
	}
}

func (d *specDecoder) decision(e *element, t *subtableSym) *decisionNode {
	e.expect(eDecision)
	n := &decisionNode{
		context:  e.bool(aContext),
		startBit: int(e.int(aStartbit)),
		size:     int(e.int(aSize)),
	}
	if n.size < 0 || n.size > 32 {
		fail("decision on %d bits", n.size)
	}
	for _, k := range e.kids {
		switch k.id {
		case ePair:
			id := k.int(aId)
			if id < 0 || id >= int64(len(t.cts)) {
				fail("decision names constructor %d of %d", id, len(t.cts))
			}
			n.pairs = append(n.pairs, decisionPair{pat: decodeDisjoint(k.child(0)), ct: t.cts[id]})
		case eDecision:
			n.kids = append(n.kids, d.decision(k, t))
		}
	}
	if n.size > 0 && len(n.kids) != 1<<n.size {
		fail("decision on %d bits has %d children", n.size, len(n.kids))
	}
	return n
}

func (d *specDecoder) expr(e *element) expr {
	switch e.id {
	case eTokenfield:
		return &tokenField{
			bigEndian: e.bool(aBigendian),
			signBit:   e.bool(aSignbit),
			bitStart:  int(e.int(aStartbit)),
			bitEnd:    int(e.int(aEndbit)),
			byteStart: int(e.int(aStartbyte)),
			byteEnd:   int(e.int(aEndbyte)),
			shift:     int(e.int(aShift)),
		}
	case eContextfield:
		return &contextField{
			signBit:   e.bool(aSignbit),
			startBit:  int(e.int(aStartbit)),
			endBit:    int(e.int(aEndbit)),
			startByte: int(e.int(aStartbyte)),
			endByte:   int(e.int(aEndbyte)),
			shift:     int(e.int(aShift)),
		}
	case eIntb:
		return constValue(e.int(aVal))
	case eOperandExp:
		ov := &operandValue{index: int(e.int(aIndex))}
		tabID, ctID := e.uint(aTable), e.uint(aCt)
		d.fixups = append(d.fixups, func() {
			t, ok := d.symbol(tabID).(*subtableSym)
			if !ok || ctID >= uint64(len(t.cts)) {
				fail("operand expression names a missing constructor")
			}
			ov.ct = t.cts[ctID]
			if ov.index < 0 || ov.index >= len(ov.ct.operands) {
				fail("operand expression names operand %d of %d", ov.index, len(ov.ct.operands))
			}
		})
		return ov
	case eStartExp:
		return startValue{}
	case eEndExp:
		return endValue{}
	case eNext2Exp:
		return next2Value{}
	case eMinusExp, eNotExp:
		return &unaryExpr{op: e.id, x: d.expr(e.child(0))}
	case ePlusExp, eSubExp, eMultExp, eLshiftExp, eRshiftExp, eAndExp, eOrExp, eXorExp, eDivExp:
		return &binaryExpr{op: e.id, l: d.expr(e.child(0)), r: d.expr(e.child(1))}
	}
	fail("unknown pattern expression <%s>", elemName(e.id))
	return nil
}

func decodeDisjoint(e *element) disjointPattern {
	switch e.id {
	case eInstructPat:
		return instructionPattern{decodeBlock(e.child(0))}
	case eContextPat:
		return contextPattern{decodeBlock(e.child(0))}
	case eCombinePat:
		return combinePattern{
			context: decodeBlock(e.child(0).child(0)),
			instr:   decodeBlock(e.child(1).child(0)),
		}
	}
	fail("unknown pattern <%s>", elemName(e.id))
	return nil
}

func decodeBlock(e *element) *patternBlock {
	e.expect(ePatBlock)
	b := &patternBlock{offset: int(e.int(aOff)), nonZero: int(e.int(aNonzero))}
	for _, k := range e.kids {
		k.expect(eMaskWord)
		b.mask = append(b.mask, uint32(k.uint(aMask)))
		b.val = append(b.val, uint32(k.uint(aVal)))
	}
	b.normalize()
	return b
}

// P-code templates.

func (d *specDecoder) constructTpl(e *element) (*constructTpl, int) {
	t := &constructTpl{}
	section := -1
	if e.has(aDelay) {
		t.delaySlot = int(e.int(aDelay))
	}
	if e.has(aLabels) {
		t.numLabels = int(e.int(aLabels))
	}
	if e.has(aSection) {
		section = int(e.int(aSection))
	}
	kids := e.kids
	if len(kids) == 0 {
		fail("empty <construct_tpl>")
	}
	if kids[0].id != eNull {
		t.result = d.handleTpl(kids[0])
	}
	for _, k := range kids[1:] {
		t.ops = append(t.ops, d.opTpl(k))
	}
	return t, section
}

func (d *specDecoder) handleTpl(e *element) *handleTpl {
	e.expect(eHandleTpl)
	if len(e.kids) != 7 {
		fail("<handle_tpl> has %d parts, want 7", len(e.kids))
	}
	return &handleTpl{
		space:      d.constTpl(e.kids[0]),
		size:       d.constTpl(e.kids[1]),
		ptrSpace:   d.constTpl(e.kids[2]),
		ptrOffset:  d.constTpl(e.kids[3]),
		ptrSize:    d.constTpl(e.kids[4]),
		tempSpace:  d.constTpl(e.kids[5]),
		tempOffset: d.constTpl(e.kids[6]),
	}
}

func (d *specDecoder) opTpl(e *element) *opTpl {
	e.expect(eOpTpl)
	op := &opTpl{code: pcodeOp(e.int(aCode))}
	if len(e.kids) == 0 {
		fail("empty <op_tpl>")
	}
	if e.kids[0].id != eNull {
		op.out = d.varnodeTpl(e.kids[0])
	}
	for _, k := range e.kids[1:] {
		op.in = append(op.in, d.varnodeTpl(k))
	}
	return op
}

func (d *specDecoder) varnodeTpl(e *element) *varnodeTpl {
	e.expect(eVarnodeTpl)
	return &varnodeTpl{
		space:  d.constTpl(e.child(0)),
		offset: d.constTpl(e.child(1)),
		size:   d.constTpl(e.child(2)),
	}
}

func (d *specDecoder) constTpl(e *element) constTpl {
	switch e.id {
	case eConstReal:
		return constTpl{kind: ctReal, real: e.uint(aVal)}
	case eConstHandle:
		c := constTpl{kind: ctHandle, handle: int(e.int(aVal)), sel: int(e.int(aS))}
		if c.sel < vSpace || c.sel > vOffsetPlus {
			fail("bad handle selector %d", c.sel)
		}
		if c.sel == vOffsetPlus {
			c.real = e.uint(aPlus)
		}
		return c
	case eConstStart:
		return constTpl{kind: ctStart}
	case eConstNext:
		return constTpl{kind: ctNext}
	case eConstNext2:
		return constTpl{kind: ctNext2}
	case eConstCurspace:
		return constTpl{kind: ctCurSpace}
	case eConstCurspaceSize:
		return constTpl{kind: ctCurSpaceSize}
	case eConstSpaceid:
		return constTpl{kind: ctSpaceID, space: d.spec.spaceAt(e.space(aSpace))}
	case eConstRelative:
		return constTpl{kind: ctRelative, real: e.uint(aVal)}
	case eConstFlowref:
		return constTpl{kind: ctFlowRef}
	case eConstFlowrefSize:
		return constTpl{kind: ctFlowRefSize}
	case eConstFlowdest:
		return constTpl{kind: ctFlowDest}
	case eConstFlowdestSize:
		return constTpl{kind: ctFlowDestSize}
	}
	fail("unknown constant template <%s>", elemName(e.id))
	return constTpl{}
}
