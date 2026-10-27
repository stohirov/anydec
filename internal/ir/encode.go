package ir

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

// EncodingVersion changes whenever the encoded form of a Function does,
// so stored IR from older versions is ignored rather than misread.
const EncodingVersion = 1

// wireFunction is a Function with block references as indices.
type wireFunction struct {
	Entry      uint64
	Name       string
	Insns      []*Insn
	Blocks     []wireBlock
	JumpTables []JumpTable
	Unresolved []uint64
	Calls      []uint64
	Warnings   []Warning
}

type wireBlock struct {
	Start uint64
	Ops   []Op
	Succ  []int
}

// Encode serializes fn, for caching it in a project database.
func (fn *Function) Encode() ([]byte, error) {
	index := map[*Block]int{}
	for i, b := range fn.Blocks {
		index[b] = i
	}
	w := wireFunction{
		Entry: fn.Entry, Name: fn.Name, Insns: fn.Insns, JumpTables: fn.JumpTables,
		Unresolved: fn.Unresolved, Calls: fn.Calls, Warnings: fn.Warnings,
	}
	for _, b := range fn.Blocks {
		wb := wireBlock{Start: b.Start, Ops: b.Ops}
		for _, s := range b.Succ {
			wb.Succ = append(wb.Succ, index[s])
		}
		w.Blocks = append(w.Blocks, wb)
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&w); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeFunction rebuilds a Function that Encode serialized, and checks
// it.
func DecodeFunction(data []byte) (*Function, error) {
	var w wireFunction
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&w); err != nil {
		return nil, err
	}
	fn := &Function{
		Entry: w.Entry, Name: w.Name, Insns: w.Insns, JumpTables: w.JumpTables,
		Unresolved: w.Unresolved, Calls: w.Calls, Warnings: w.Warnings,
	}
	fn.Blocks = make([]*Block, len(w.Blocks))
	for i, wb := range w.Blocks {
		fn.Blocks[i] = &Block{Start: wb.Start, Ops: wb.Ops}
	}
	for i, wb := range w.Blocks {
		b := fn.Blocks[i]
		for _, s := range wb.Succ {
			if s < 0 || s >= len(fn.Blocks) {
				return nil, fmt.Errorf("%s: successor index %d out of range", fn.Name, s)
			}
			b.Succ = append(b.Succ, fn.Blocks[s])
			fn.Blocks[s].Pred = append(fn.Blocks[s].Pred, b)
		}
	}
	if err := fn.Verify(); err != nil {
		return nil, err
	}
	return fn, nil
}
