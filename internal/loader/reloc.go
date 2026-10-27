package loader

import (
	"debug/elf"
	"encoding/binary"
)

// Static relocation of objects, following each architecture's ELF ABI
// (AAELF for ARM, AAELF64 for AArch64, the System V x86-64 psABI). Formulas
// use the ABI names: S is the symbol's address, A the addend, P the place
// patched, and T is 1 when S is a Thumb function. Relocations that need a
// GOT, a PLT or a veneer are left unapplied.

// relocTarget is a relocation's resolved symbol.
type relocTarget struct {
	addr  uint64 // S
	ok    bool   // the symbol has an address
	thumb bool   // T: an ARM function symbol with the Thumb bit set
	arm   bool   // an ARM function symbol in ARM state
}

func resolveSymbol(f *elf.File, s elf.Symbol, sectionAddr []uint64, externs map[string]uint64) relocTarget {
	var t relocTarget
	switch {
	case s.Section == elf.SHN_UNDEF:
		t.addr, t.ok = externs[s.Name]
	case s.Section == elf.SHN_ABS:
		t.addr, t.ok = s.Value, true
	case s.Section < elf.SHN_LORESERVE && int(s.Section) < len(sectionAddr):
		t.addr, t.ok = s.Value+sectionAddr[s.Section], true
	}
	if f.Machine == elf.EM_ARM && elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Section != elf.SHN_UNDEF {
		t.thumb = t.addr&1 != 0
		t.arm = !t.thumb
		t.addr &^= 1
	}
	return t
}

// applyReloc patches the bytes at r.Addr and reports whether it knew how.
func (p *Program) applyReloc(f *elf.File, r Relocation, t relocTarget) bool {
	size := 4
	if (f.Machine == elf.EM_AARCH64 && (r.Type == 257 || r.Type == 260)) ||
		(f.Machine == elf.EM_X86_64 && (r.Type == 1 || r.Type == 24)) {
		size = 8
	}
	seg := p.Segment(r.Addr)
	if seg == nil || r.Addr+uint64(size) > seg.End() {
		return false
	}
	b := seg.Data[r.Addr-seg.Addr:][:size]
	switch f.Machine {
	case elf.EM_ARM:
		return relocARM(f.ByteOrder, b, r, t)
	case elf.EM_AARCH64:
		return relocAArch64(f.ByteOrder, b, r, t)
	case elf.EM_X86_64:
		return relocX86_64(f.ByteOrder, b, r, t)
	}
	return false
}

func signExtend(v uint64, bits int) int64 {
	sh := 64 - bits
	return int64(v<<sh) >> sh
}

// fits reports whether v is a signed value of the given width.
func fits(v int64, bits int) bool {
	return v >= -(1<<(bits-1)) && v < 1<<(bits-1)
}

// ARM relocation types (AAELF).
const (
	rARMThmCall      = 10
	rARMAbs32        = 2
	rARMRel32        = 3
	rARMCall         = 28
	rARMJump24       = 29
	rARMThmJump24    = 30
	rARMPrel31       = 42
	rARMMovwAbsNC    = 43
	rARMMovtAbs      = 44
	rARMThmMovwAbsNC = 47
	rARMThmMovtAbs   = 48

	armBranchRange   = 26  // bits of an ARM B/BL offset
	thumbBranchRange = 25  // bits of a Thumb-2 B.W/BL offset
	armUncond        = 0xf // condition field of BLX (immediate)
)

func relocARM(bo binary.ByteOrder, b []byte, r Relocation, t relocTarget) bool {
	S, P := t.addr, r.Addr
	var T uint64
	if t.thumb {
		T = 1
	}
	switch r.Type {
	case rARMAbs32:
		bo.PutUint32(b, uint32((S+uint64(int64(int32(bo.Uint32(b)))))|T))
	case rARMRel32:
		bo.PutUint32(b, uint32((S+uint64(int64(int32(bo.Uint32(b))))|T)-P))
	case rARMPrel31:
		w := bo.Uint32(b)
		v := ((S + uint64(signExtend(uint64(w), 31))) | T) - P
		bo.PutUint32(b, w&0x80000000|uint32(v)&0x7fffffff)
	case rARMCall, rARMJump24:
		w := bo.Uint32(b)
		A := signExtend(uint64(w&0xffffff)<<2, armBranchRange)
		v := int64(S+uint64(A)) - int64(P)
		if !fits(v, armBranchRange) {
			return false
		}
		switch {
		case t.thumb && r.Type == rARMJump24:
			return false // needs an interworking veneer
		case t.thumb: // BL to Thumb becomes BLX, with offset bit 1 in H
			w = 0xfa000000 | uint32(v>>1&1)<<24
		case w>>28 == armUncond && t.arm: // BLX to ARM becomes BL
			w = 0xeb000000
		}
		bo.PutUint32(b, w&0xff000000|uint32(v>>2)&0xffffff)
	case rARMMovwAbsNC, rARMMovtAbs:
		w := bo.Uint32(b)
		A := signExtend(uint64(w>>4&0xf000|w&0xfff), 16)
		v := S + uint64(A)
		if r.Type == rARMMovwAbsNC {
			v |= T
		} else {
			v >>= 16
		}
		bo.PutUint32(b, w&0xfff0f000|uint32(v>>12&0xf)<<16|uint32(v&0xfff))
	case rARMThmCall, rARMThmJump24:
		hi, lo := bo.Uint16(b), bo.Uint16(b[2:])
		A := signExtend(thumbBranchImm(hi, lo), thumbBranchRange)
		blx := r.Type == rARMThmCall && t.arm
		place := P
		if blx {
			place &^= 3 // BLX offsets are from Align(PC, 4)
		}
		v := int64(S+uint64(A)) - int64(place)
		if !fits(v, thumbBranchRange) || (r.Type == rARMThmJump24 && t.arm) {
			return false
		}
		switch {
		case blx:
			lo &^= 1 << 12
		case r.Type == rARMThmCall && t.thumb:
			lo |= 1 << 12 // BLX to Thumb becomes BL
		}
		hi, lo = putThumbBranchImm(hi, lo, uint64(v))
		bo.PutUint16(b, hi)
		bo.PutUint16(b[2:], lo)
	case rARMThmMovwAbsNC, rARMThmMovtAbs:
		hi, lo := bo.Uint16(b), bo.Uint16(b[2:])
		imm := uint64(hi&0xf)<<12 | uint64(hi>>10&1)<<11 | uint64(lo>>12&7)<<8 | uint64(lo&0xff)
		v := S + uint64(signExtend(imm, 16))
		if r.Type == rARMThmMovwAbsNC {
			v |= T
		} else {
			v >>= 16
		}
		hi = hi&0xfbf0 | uint16(v>>12&0xf) | uint16(v>>11&1)<<10
		lo = lo&0x8f00 | uint16(v>>8&7)<<12 | uint16(v&0xff)
		bo.PutUint16(b, hi)
		bo.PutUint16(b[2:], lo)
	default:
		return false
	}
	return true
}

// thumbBranchImm decodes the offset field of a Thumb-2 BL, BLX or B.W:
// S:I1:I2:imm10:imm11:0, with I1 = NOT(J1 XOR S) and I2 = NOT(J2 XOR S).
func thumbBranchImm(hi, lo uint16) uint64 {
	s := uint64(hi >> 10 & 1)
	j1, j2 := uint64(lo>>13&1), uint64(lo>>11&1)
	i1, i2 := ^(j1^s)&1, ^(j2^s)&1
	return s<<24 | i1<<23 | i2<<22 | uint64(hi&0x3ff)<<12 | uint64(lo&0x7ff)<<1
}

func putThumbBranchImm(hi, lo uint16, v uint64) (uint16, uint16) {
	s := v >> 24 & 1
	i1, i2 := v>>23&1, v>>22&1
	j1, j2 := ^(i1^s)&1, ^(i2^s)&1
	hi = hi&0xf800 | uint16(s)<<10 | uint16(v>>12&0x3ff)
	lo = lo&0xd000 | uint16(j1)<<13 | uint16(j2)<<11 | uint16(v>>1&0x7ff)
	return hi, lo
}

// AArch64 relocation types (AAELF64).
const (
	rA64Abs64         = 257
	rA64Abs32         = 258
	rA64Prel64        = 260
	rA64Prel32        = 261
	rA64AdrPrelLo21   = 274
	rA64AdrPrelPgHi21 = 275
	rA64AddAbsLo12NC  = 277
	rA64Ldst8AbsLo12  = 278
	rA64TstBr14       = 279
	rA64CondBr19      = 280
	rA64Jump26        = 282
	rA64Call26        = 283
	rA64Ldst16AbsLo12 = 284
	rA64Ldst32AbsLo12 = 285
	rA64Ldst64AbsLo12 = 286
	rA64Ldst128Lo12   = 299
)

func relocAArch64(bo binary.ByteOrder, b []byte, r Relocation, t relocTarget) bool {
	SA := t.addr + uint64(r.Addend)
	P := r.Addr
	// AArch64 instructions are always little-endian.
	insn := binary.LittleEndian.Uint32(b)
	put := func(w uint32) { binary.LittleEndian.PutUint32(b, w) }
	switch r.Type {
	case rA64Abs64:
		bo.PutUint64(b, SA)
	case rA64Prel64:
		bo.PutUint64(b, SA-P)
	case rA64Abs32:
		bo.PutUint32(b, uint32(SA))
	case rA64Prel32:
		bo.PutUint32(b, uint32(SA-P))
	case rA64AdrPrelLo21, rA64AdrPrelPgHi21:
		v := int64(SA - P)
		if r.Type == rA64AdrPrelPgHi21 {
			v = int64(SA&^0xfff-P&^0xfff) >> 12
		}
		if !fits(v, 21) {
			return false
		}
		put(insn&0x9f00001f | uint32(v&3)<<29 | uint32(v>>2&0x7ffff)<<5)
	case rA64AddAbsLo12NC, rA64Ldst8AbsLo12, rA64Ldst16AbsLo12, rA64Ldst32AbsLo12, rA64Ldst64AbsLo12, rA64Ldst128Lo12:
		shift := map[uint32]uint{rA64Ldst16AbsLo12: 1, rA64Ldst32AbsLo12: 2, rA64Ldst64AbsLo12: 3, rA64Ldst128Lo12: 4}[r.Type]
		put(insn&^(0xfff<<10) | uint32((SA&0xfff)>>shift)<<10)
	case rA64Jump26, rA64Call26:
		v := int64(SA - P)
		if !fits(v, 28) {
			return false
		}
		put(insn&0xfc000000 | uint32(v>>2)&0x3ffffff)
	case rA64CondBr19:
		v := int64(SA - P)
		if !fits(v, 21) {
			return false
		}
		put(insn&^(0x7ffff<<5) | uint32(v>>2&0x7ffff)<<5)
	case rA64TstBr14:
		v := int64(SA - P)
		if !fits(v, 16) {
			return false
		}
		put(insn&^(0x3fff<<5) | uint32(v>>2&0x3fff)<<5)
	default:
		return false
	}
	return true
}

// x86-64 relocation types (System V psABI).
const (
	rX64_64   = 1
	rX64PC32  = 2
	rX64PLT32 = 4
	rX64_32   = 10
	rX64_32S  = 11
	rX64PC64  = 24
)

func relocX86_64(bo binary.ByteOrder, b []byte, r Relocation, t relocTarget) bool {
	SA := t.addr + uint64(r.Addend)
	P := r.Addr
	switch r.Type {
	case rX64_64:
		bo.PutUint64(b, SA)
	case rX64PC64:
		bo.PutUint64(b, SA-P)
	case rX64PC32, rX64PLT32: // a PLT entry would be at S, so L = S
		v := int64(SA - P)
		if !fits(v, 32) {
			return false
		}
		bo.PutUint32(b, uint32(v))
	case rX64_32:
		if SA > 0xffffffff {
			return false
		}
		bo.PutUint32(b, uint32(SA))
	case rX64_32S:
		if !fits(int64(SA), 32) {
			return false
		}
		bo.PutUint32(b, uint32(SA))
	default:
		return false
	}
	return true
}
