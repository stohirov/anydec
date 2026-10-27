package sleigh

import "sort"

// contextDB tracks context register values across the address space, as
// Ghidra's ContextInternal does: a partition of addresses into regions,
// each with full context words plus a mask of bits explicitly set there.
// A flowing change runs from its address until the next region that set
// the same bits.
type contextDB struct {
	words    int
	defaults []uint32
	points   []ctxPoint // sorted by addr
}

type ctxPoint struct {
	addr  uint64
	vals  []uint32
	masks []uint32
}

func newContextDB(words int) *contextDB {
	return &contextDB{words: words, defaults: make([]uint32, words)}
}

// region returns the index of the point governing addr, or -1 for the
// defaults.
func (db *contextDB) region(addr uint64) int {
	return sort.Search(len(db.points), func(i int) bool { return db.points[i].addr > addr }) - 1
}

func (db *contextDB) get(addr uint64, dst []uint32) {
	if i := db.region(addr); i >= 0 {
		copy(dst, db.points[i].vals)
		return
	}
	copy(dst, db.defaults)
}

// split makes addr the start of a region and returns its index. The new
// region copies its predecessor's values but none of its set marks.
func (db *contextDB) split(addr uint64) int {
	i := db.region(addr)
	if i >= 0 && db.points[i].addr == addr {
		return i
	}
	src := db.defaults
	if i >= 0 {
		src = db.points[i].vals
	}
	p := ctxPoint{addr: addr, vals: append([]uint32(nil), src...), masks: make([]uint32, db.words)}
	db.points = append(db.points, ctxPoint{})
	copy(db.points[i+2:], db.points[i+1:])
	db.points[i+1] = p
	return i + 1
}

// setChangePoint sets bits from addr onward, stopping at the next region
// that set any of the same bits itself.
func (db *contextDB) setChangePoint(addr uint64, num int, mask, value uint32) {
	i := db.split(addr)
	db.points[i].masks[num] |= mask
	db.points[i].vals[num] = db.points[i].vals[num]&^mask | value
	for i++; i < len(db.points); i++ {
		if db.points[i].masks[num]&mask != 0 {
			break
		}
		db.points[i].vals[num] = db.points[i].vals[num]&^mask | value
	}
}

// setRegion sets bits for addresses in [addr, end) only; end 0 means to the
// end of the address space.
func (db *contextDB) setRegion(addr, end uint64, num int, mask, value uint32) {
	i := db.split(addr)
	stop := len(db.points)
	if end != 0 {
		stop = db.split(end)
	}
	for ; i < stop; i++ {
		db.points[i].masks[num] |= mask
		db.points[i].vals[num] = db.points[i].vals[num]&^mask | value
	}
}
