package ir

// Opcode follows Ghidra's P-code opcode set, so SLEIGH output translates
// one-to-one. PHI is P-code's MULTIEQUAL.
type Opcode uint8

const (
	OpInvalid Opcode = iota

	// Data movement and memory.
	OpCopy
	OpLoad
	OpStore

	// Control flow.
	OpBranch
	OpCBranch
	OpBranchInd
	OpCall
	OpCallInd
	OpCallOther
	OpReturn

	// Integer compares.
	OpIntEqual
	OpIntNotEqual
	OpIntSLess
	OpIntSLessEqual
	OpIntLess
	OpIntLessEqual

	// Integer arithmetic and logic.
	OpIntZExt
	OpIntSExt
	OpIntAdd
	OpIntSub
	OpIntCarry
	OpIntSCarry
	OpIntSBorrow
	OpInt2Comp
	OpIntNegate
	OpIntXor
	OpIntAnd
	OpIntOr
	OpIntLeft
	OpIntRight
	OpIntSRight
	OpIntMult
	OpIntDiv
	OpIntSDiv
	OpIntRem
	OpIntSRem
	OpPopCount
	OpLzCount

	// Booleans.
	OpBoolNegate
	OpBoolXor
	OpBoolAnd
	OpBoolOr

	// Floating point.
	OpFloatEqual
	OpFloatNotEqual
	OpFloatLess
	OpFloatLessEqual
	OpFloatNaN
	OpFloatAdd
	OpFloatSub
	OpFloatMult
	OpFloatDiv
	OpFloatNeg
	OpFloatAbs
	OpFloatSqrt
	OpFloatInt2Float
	OpFloatFloat2Float
	OpFloatTrunc
	OpFloatCeil
	OpFloatFloor
	OpFloatRound

	// SSA and analysis-only ops.
	OpPhi
	OpIndirect
	OpPiece
	OpSubpiece
	OpCast
	OpPtrAdd
	OpPtrSub
	OpSegmentOp
	OpCPoolRef
	OpNew
	OpInsert
	OpExtract

	opcodeCount
)

var opcodeNames = [opcodeCount]string{
	OpInvalid: "INVALID",
	OpCopy:    "COPY", OpLoad: "LOAD", OpStore: "STORE",
	OpBranch: "BRANCH", OpCBranch: "CBRANCH", OpBranchInd: "BRANCHIND",
	OpCall: "CALL", OpCallInd: "CALLIND", OpCallOther: "CALLOTHER", OpReturn: "RETURN",
	OpIntEqual: "INT_EQUAL", OpIntNotEqual: "INT_NOTEQUAL",
	OpIntSLess: "INT_SLESS", OpIntSLessEqual: "INT_SLESSEQUAL",
	OpIntLess: "INT_LESS", OpIntLessEqual: "INT_LESSEQUAL",
	OpIntZExt: "INT_ZEXT", OpIntSExt: "INT_SEXT",
	OpIntAdd: "INT_ADD", OpIntSub: "INT_SUB",
	OpIntCarry: "INT_CARRY", OpIntSCarry: "INT_SCARRY", OpIntSBorrow: "INT_SBORROW",
	OpInt2Comp: "INT_2COMP", OpIntNegate: "INT_NEGATE",
	OpIntXor: "INT_XOR", OpIntAnd: "INT_AND", OpIntOr: "INT_OR",
	OpIntLeft: "INT_LEFT", OpIntRight: "INT_RIGHT", OpIntSRight: "INT_SRIGHT",
	OpIntMult: "INT_MULT", OpIntDiv: "INT_DIV", OpIntSDiv: "INT_SDIV",
	OpIntRem: "INT_REM", OpIntSRem: "INT_SREM",
	OpPopCount: "POPCOUNT", OpLzCount: "LZCOUNT",
	OpBoolNegate: "BOOL_NEGATE", OpBoolXor: "BOOL_XOR", OpBoolAnd: "BOOL_AND", OpBoolOr: "BOOL_OR",
	OpFloatEqual: "FLOAT_EQUAL", OpFloatNotEqual: "FLOAT_NOTEQUAL",
	OpFloatLess: "FLOAT_LESS", OpFloatLessEqual: "FLOAT_LESSEQUAL", OpFloatNaN: "FLOAT_NAN",
	OpFloatAdd: "FLOAT_ADD", OpFloatSub: "FLOAT_SUB", OpFloatMult: "FLOAT_MULT", OpFloatDiv: "FLOAT_DIV",
	OpFloatNeg: "FLOAT_NEG", OpFloatAbs: "FLOAT_ABS", OpFloatSqrt: "FLOAT_SQRT",
	OpFloatInt2Float: "FLOAT_INT2FLOAT", OpFloatFloat2Float: "FLOAT_FLOAT2FLOAT",
	OpFloatTrunc: "FLOAT_TRUNC", OpFloatCeil: "FLOAT_CEIL", OpFloatFloor: "FLOAT_FLOOR", OpFloatRound: "FLOAT_ROUND",
	OpPhi: "PHI", OpIndirect: "INDIRECT", OpPiece: "PIECE", OpSubpiece: "SUBPIECE",
	OpCast: "CAST", OpPtrAdd: "PTRADD", OpPtrSub: "PTRSUB", OpSegmentOp: "SEGMENTOP",
	OpCPoolRef: "CPOOLREF", OpNew: "NEW", OpInsert: "INSERT", OpExtract: "EXTRACT",
}

func (o Opcode) String() string {
	if o < opcodeCount && opcodeNames[o] != "" {
		return opcodeNames[o]
	}
	return "UNKNOWN"
}
