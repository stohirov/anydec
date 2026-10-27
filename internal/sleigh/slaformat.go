// Code generated from Ghidra's slaformat.cc (Ghidra_12.2_build). DO NOT EDIT.

package sleigh

// slaVersion is the .sla format version this runtime reads.
const slaVersion = 4

// Attribute ids of the .sla packed encoding.
const (
	aVal          = 2  // val
	aId           = 3  // id
	aSpace        = 4  // space
	aS            = 5  // s
	aOff          = 6  // off
	aCode         = 7  // code
	aMask         = 8  // mask
	aIndex        = 9  // index
	aNonzero      = 10 // nonzero
	aPiece        = 11 // piece
	aName         = 12 // name
	aScope        = 13 // scope
	aStartbit     = 14 // startbit
	aSize         = 15 // size
	aTable        = 16 // table
	aCt           = 17 // ct
	aMinlen       = 18 // minlen
	aBase         = 19 // base
	aNumber       = 20 // number
	aContext      = 21 // context
	aParent       = 22 // parent
	aSubsym       = 23 // subsym
	aLine         = 24 // line
	aSource       = 25 // source
	aLength       = 26 // length
	aFirst        = 27 // first
	aPlus         = 28 // plus
	aShift        = 29 // shift
	aEndbit       = 30 // endbit
	aSignbit      = 31 // signbit
	aEndbyte      = 32 // endbyte
	aStartbyte    = 33 // startbyte
	aVersion      = 34 // version
	aBigendian    = 35 // bigendian
	aAlign        = 36 // align
	aUniqbase     = 37 // uniqbase
	aMaxdelay     = 38 // maxdelay
	aUniqmask     = 39 // uniqmask
	aNumsections  = 40 // numsections
	aDefaultspace = 41 // defaultspace
	aDelay        = 42 // delay
	aWordsize     = 43 // wordsize
	aPhysical     = 44 // physical
	aScopesize    = 45 // scopesize
	aSymbolsize   = 46 // symbolsize
	aVarnode      = 47 // varnode
	aLow          = 48 // low
	aHigh         = 49 // high
	aFlow         = 50 // flow
	aContain      = 51 // contain
	aI            = 52 // i
	aNumct        = 53 // numct
	aSection      = 54 // section
	aLabels       = 55 // labels
)

// Element ids of the .sla packed encoding.
const (
	eConstReal         = 1  // const_real
	eVarnodeTpl        = 2  // varnode_tpl
	eConstSpaceid      = 3  // const_spaceid
	eConstHandle       = 4  // const_handle
	eOpTpl             = 5  // op_tpl
	eMaskWord          = 6  // mask_word
	ePatBlock          = 7  // pat_block
	ePrint             = 8  // print
	ePair              = 9  // pair
	eContextPat        = 10 // context_pat
	eNull              = 11 // null
	eOperandExp        = 12 // operand_exp
	eOperandSym        = 13 // operand_sym
	eOperandSymHead    = 14 // operand_sym_head
	eOper              = 15 // oper
	eDecision          = 16 // decision
	eOpprint           = 17 // opprint
	eInstructPat       = 18 // instruct_pat
	eCombinePat        = 19 // combine_pat
	eConstructor       = 20 // constructor
	eConstructTpl      = 21 // construct_tpl
	eScope             = 22 // scope
	eVarnodeSym        = 23 // varnode_sym
	eVarnodeSymHead    = 24 // varnode_sym_head
	eUserop            = 25 // userop
	eUseropHead        = 26 // userop_head
	eTokenfield        = 27 // tokenfield
	eVar               = 28 // var
	eContextfield      = 29 // contextfield
	eHandleTpl         = 30 // handle_tpl
	eConstRelative     = 31 // const_relative
	eContextOp         = 32 // context_op
	eSleigh            = 33 // sleigh
	eSpaces            = 34 // spaces
	eSourcefiles       = 35 // sourcefiles
	eSourcefile        = 36 // sourcefile
	eSpace             = 37 // space
	eSymbolTable       = 38 // symbol_table
	eValueSym          = 39 // value_sym
	eValueSymHead      = 40 // value_sym_head
	eContextSym        = 41 // context_sym
	eContextSymHead    = 42 // context_sym_head
	eEndSym            = 43 // end_sym
	eEndSymHead        = 44 // end_sym_head
	eSpaceOther        = 45 // space_other
	eSpaceUnique       = 46 // space_unique
	eAndExp            = 47 // and_exp
	eDivExp            = 48 // div_exp
	eLshiftExp         = 49 // lshift_exp
	eMinusExp          = 50 // minus_exp
	eMultExp           = 51 // mult_exp
	eNotExp            = 52 // not_exp
	eOrExp             = 53 // or_exp
	ePlusExp           = 54 // plus_exp
	eRshiftExp         = 55 // rshift_exp
	eSubExp            = 56 // sub_exp
	eXorExp            = 57 // xor_exp
	eIntb              = 58 // intb
	eEndExp            = 59 // end_exp
	eNext2Exp          = 60 // next2_exp
	eStartExp          = 61 // start_exp
	eEpsilonSym        = 62 // epsilon_sym
	eEpsilonSymHead    = 63 // epsilon_sym_head
	eNameSym           = 64 // name_sym
	eNameSymHead       = 65 // name_sym_head
	eNametab           = 66 // nametab
	eNext2Sym          = 67 // next2_sym
	eNext2SymHead      = 68 // next2_sym_head
	eStartSym          = 69 // start_sym
	eStartSymHead      = 70 // start_sym_head
	eSubtableSym       = 71 // subtable_sym
	eSubtableSymHead   = 72 // subtable_sym_head
	eValuemapSym       = 73 // valuemap_sym
	eValuemapSymHead   = 74 // valuemap_sym_head
	eValuetab          = 75 // valuetab
	eVarlistSym        = 76 // varlist_sym
	eVarlistSymHead    = 77 // varlist_sym_head
	eOrPat             = 78 // or_pat
	eCommit            = 79 // commit
	eConstStart        = 80 // const_start
	eConstNext         = 81 // const_next
	eConstNext2        = 82 // const_next2
	eConstCurspace     = 83 // const_curspace
	eConstCurspaceSize = 84 // const_curspace_size
	eConstFlowref      = 85 // const_flowref
	eConstFlowrefSize  = 86 // const_flowref_size
	eConstFlowdest     = 87 // const_flowdest
	eConstFlowdestSize = 88 // const_flowdest_size
)

var attrNames = map[uint32]string{
	2:  "val",
	3:  "id",
	4:  "space",
	5:  "s",
	6:  "off",
	7:  "code",
	8:  "mask",
	9:  "index",
	10: "nonzero",
	11: "piece",
	12: "name",
	13: "scope",
	14: "startbit",
	15: "size",
	16: "table",
	17: "ct",
	18: "minlen",
	19: "base",
	20: "number",
	21: "context",
	22: "parent",
	23: "subsym",
	24: "line",
	25: "source",
	26: "length",
	27: "first",
	28: "plus",
	29: "shift",
	30: "endbit",
	31: "signbit",
	32: "endbyte",
	33: "startbyte",
	34: "version",
	35: "bigendian",
	36: "align",
	37: "uniqbase",
	38: "maxdelay",
	39: "uniqmask",
	40: "numsections",
	41: "defaultspace",
	42: "delay",
	43: "wordsize",
	44: "physical",
	45: "scopesize",
	46: "symbolsize",
	47: "varnode",
	48: "low",
	49: "high",
	50: "flow",
	51: "contain",
	52: "i",
	53: "numct",
	54: "section",
	55: "labels",
}

var elemNames = map[uint32]string{
	1:  "const_real",
	2:  "varnode_tpl",
	3:  "const_spaceid",
	4:  "const_handle",
	5:  "op_tpl",
	6:  "mask_word",
	7:  "pat_block",
	8:  "print",
	9:  "pair",
	10: "context_pat",
	11: "null",
	12: "operand_exp",
	13: "operand_sym",
	14: "operand_sym_head",
	15: "oper",
	16: "decision",
	17: "opprint",
	18: "instruct_pat",
	19: "combine_pat",
	20: "constructor",
	21: "construct_tpl",
	22: "scope",
	23: "varnode_sym",
	24: "varnode_sym_head",
	25: "userop",
	26: "userop_head",
	27: "tokenfield",
	28: "var",
	29: "contextfield",
	30: "handle_tpl",
	31: "const_relative",
	32: "context_op",
	33: "sleigh",
	34: "spaces",
	35: "sourcefiles",
	36: "sourcefile",
	37: "space",
	38: "symbol_table",
	39: "value_sym",
	40: "value_sym_head",
	41: "context_sym",
	42: "context_sym_head",
	43: "end_sym",
	44: "end_sym_head",
	45: "space_other",
	46: "space_unique",
	47: "and_exp",
	48: "div_exp",
	49: "lshift_exp",
	50: "minus_exp",
	51: "mult_exp",
	52: "not_exp",
	53: "or_exp",
	54: "plus_exp",
	55: "rshift_exp",
	56: "sub_exp",
	57: "xor_exp",
	58: "intb",
	59: "end_exp",
	60: "next2_exp",
	61: "start_exp",
	62: "epsilon_sym",
	63: "epsilon_sym_head",
	64: "name_sym",
	65: "name_sym_head",
	66: "nametab",
	67: "next2_sym",
	68: "next2_sym_head",
	69: "start_sym",
	70: "start_sym_head",
	71: "subtable_sym",
	72: "subtable_sym_head",
	73: "valuemap_sym",
	74: "valuemap_sym_head",
	75: "valuetab",
	76: "varlist_sym",
	77: "varlist_sym_head",
	78: "or_pat",
	79: "commit",
	80: "const_start",
	81: "const_next",
	82: "const_next2",
	83: "const_curspace",
	84: "const_curspace_size",
	85: "const_flowref",
	86: "const_flowref_size",
	87: "const_flowdest",
	88: "const_flowdest_size",
}
