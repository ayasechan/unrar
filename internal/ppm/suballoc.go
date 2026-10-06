package ppm

// 子分配器：PPM 模型的 arena 内存管理。
//
// 对齐参考实现的 12 字节 UNIT_SIZE（x86-64 打包布局）：
// MEM_BLK = Stamp u16 + NU u16 + next/prev 链接；
// CONTEXT = NumStats u16 + SummFreq u16 + Stats 偏移 + Suffix 偏移；
// STATE = Symbol + Freq + Successor 偏移（6 字节）。
// 所有堆内链接用偏移表示，0 = 空（arena 对象永不落在偏移 0）。

const (
	unitSize  = 12
	fixedUnit = 12
	n1        = 4
	n2        = 4
	n3        = 4
	n4        = (128 + 3 - 1*n1 - 2*n2 - 3*n3) / 4
	nIndexes  = n1 + n2 + n3 + n4
)

type subAlloc struct {
	size           int // 已分配字节（SubAllocatorSize）。
	indx2units     [nIndexes]int
	units2indx     [128]int
	glueCount      byte
	heap           []byte
	loUnit         int
	hiUnit         int
	unitsStart     int
	heapEnd        int
	fakeUnitsStart int
	pText          int
	freeList       [nIndexes]int
}

func (s *subAlloc) getU16(off int) uint16 {
	return uint16(s.heap[off]) | uint16(s.heap[off+1])<<8
}

func (s *subAlloc) setU16(off int, v uint16) {
	s.heap[off] = byte(v)
	s.heap[off+1] = byte(v >> 8)
}

func (s *subAlloc) getU32(off int) int {
	return int(uint32(s.heap[off]) | uint32(s.heap[off+1])<<8 |
		uint32(s.heap[off+2])<<16 | uint32(s.heap[off+3])<<24)
}

func (s *subAlloc) setU32(off, v int) {
	s.heap[off] = byte(v)
	s.heap[off+1] = byte(v >> 8)
	s.heap[off+2] = byte(v >> 16)
	s.heap[off+3] = byte(v >> 24)
}

func u2b(nu int) int { return unitSize * nu }

func (s *subAlloc) insertNode(p, indx int) {
	s.setU32(p, s.freeList[indx])
	s.freeList[indx] = p
}

func (s *subAlloc) removeNode(indx int) int {
	ret := s.freeList[indx]
	s.freeList[indx] = s.getU32(ret)
	return ret
}

func (s *subAlloc) splitBlock(pv, oldIndx, newIndx int) {
	udiff := s.indx2units[oldIndx] - s.indx2units[newIndx]
	p := pv + u2b(s.indx2units[newIndx])
	i := 0
	if s.indx2units[s.units2indx[udiff-1]] != udiff {
		i = s.units2indx[udiff-1] - 1
		s.insertNode(p, i)
		p += u2b(s.indx2units[i])
		udiff -= s.indx2units[i]
	}
	s.insertNode(p, s.units2indx[udiff-1])
	_ = i
}

// glueFreeBlocks 合并空闲块。哨兵用 Go 变量承载，-1 表空。
func (s *subAlloc) glueFreeBlocks() {
	if s.loUnit != s.hiUnit {
		s.heap[s.loUnit] = 0
	}
	const none = -1 // 哨兵只活在 Go 变量里；堆内空链接一律存 0。
	var sNext, sPrev int = none, none
	// toHeap 把链接值转为堆内存表示（none → 0）。
	toHeap := func(v int) int {
		if v == none {
			return 0
		}
		return v
	}
	// fromHeap 把堆内存表示转回（0 → none）。
	fromHeap := func(v int) int {
		if v == 0 {
			return none
		}
		return v
	}
	getNext := func(off int) int {
		if off == none {
			return sNext
		}
		return fromHeap(s.getU32(off + 4))
	}
	getPrev := func(off int) int {
		if off == none {
			return sPrev
		}
		return fromHeap(s.getU32(off + 8))
	}
	setNext := func(off, v int) {
		if off == none {
			sNext = v
		} else {
			s.setU32(off+4, toHeap(v))
		}
	}
	setPrev := func(off, v int) {
		if off == none {
			sPrev = v
		} else {
			s.setU32(off+8, toHeap(v))
		}
	}
	insertHead := func(p int) {
		oldFirst := sNext
		setPrev(p, none)
		setNext(p, oldFirst)
		if oldFirst != none {
			setPrev(oldFirst, p)
		} else {
			sPrev = p
		}
		sNext = p
	}
	remove := func(p int) {
		pp := getPrev(p)
		if p == sNext {
			pp = none
		}
		pn := getNext(p)
		setNext(pp, pn)
		setPrev(pn, pp)
	}
	for i := 0; i < nIndexes; i++ {
		for s.freeList[i] != 0 {
			p := s.removeNode(i)
			insertHead(p)
			s.setU16(p, 0xFFFF)
			s.setU16(p+2, uint16(s.indx2units[i]))
		}
	}
	// 合并相邻块（Stamp 越界一律视为不可合并）。
	inHeap := func(off int) bool { return off >= 0 && off+12 <= len(s.heap) }
	for p := sNext; p != none; p = getNext(p) {
		for {
			p1 := p + u2b(int(s.getU16(p+2)))
			if !inHeap(p1) || s.getU16(p1) != 0xFFFF {
				break
			}
			if int(s.getU16(p+2))+int(s.getU16(p1+2)) >= 0x10000 {
				break
			}
			remove(p1)
			s.setU16(p+2, s.getU16(p+2)+s.getU16(p1+2))
		}
	}
	for sNext != none {
		p := sNext
		remove(p)
		sz := int(s.getU16(p + 2))
		for ; sz > 128; sz -= 128 {
			s.insertNode(p, nIndexes-1)
			p += u2b(128)
		}
		i := s.units2indx[sz-1]
		if s.indx2units[i] != sz {
			i--
			k := sz - s.indx2units[i]
			s.insertNode(p+u2b(sz-k), k-1)
		}
		s.insertNode(p, i)
	}
}

// startSubAllocator 分配 SASize MB 的 arena。
func (s *subAlloc) startSubAllocator(mb int) bool {
	t := mb << 20
	if s.size == t {
		return true
	}
	s.stopSubAllocator()
	allocSize := t/fixedUnit*unitSize + 2*unitSize
	s.heap = make([]byte, allocSize)
	s.heapEnd = allocSize - unitSize
	s.size = t
	return true
}

// stopSubAllocator 释放 arena。
func (s *subAlloc) stopSubAllocator() {
	if s.size != 0 {
		s.size = 0
		s.heap = nil
	}
}

// initSubAllocator 初始化空闲表与指针。
func (s *subAlloc) initSubAllocator() {
	for i := range s.freeList {
		s.freeList[i] = 0
	}
	s.pText = 0
	size2 := fixedUnit * (s.size / 8 / fixedUnit * 7)
	realSize2 := size2 / fixedUnit * unitSize
	size1 := s.size - size2
	realSize1 := size1/fixedUnit*unitSize + unitSize
	s.loUnit = realSize1
	s.unitsStart = realSize1
	s.fakeUnitsStart = size1
	s.hiUnit = s.loUnit + realSize2
	i, k := 0, 1
	for ; i < n1; i++ {
		s.indx2units[i] = k
		k++
	}
	k++
	for ; i < n1+n2; i++ {
		s.indx2units[i] = k
		k += 2
	}
	k++
	for ; i < n1+n2+n3; i++ {
		s.indx2units[i] = k
		k += 3
	}
	k++
	for ; i < n1+n2+n3+n4; i++ {
		s.indx2units[i] = k
		k += 4
	}
	s.glueCount = 0
	i = 0
	for kk := 0; kk < 128; kk++ {
		if s.indx2units[i] < kk+1 {
			i++
		}
		s.units2indx[kk] = i
	}
}

// allocUnitsRare 慢速分配。
func (s *subAlloc) allocUnitsRare(indx int) int {
	if s.glueCount == 0 {
		s.glueCount = 255
		s.glueFreeBlocks()
		if s.freeList[indx] != 0 {
			return s.removeNode(indx)
		}
	}
	i := indx
	for {
		i++
		if i == nIndexes {
			s.glueCount--
			n := u2b(s.indx2units[indx])
			j := 12 * s.indx2units[indx]
			if s.fakeUnitsStart-s.pText > j {
				s.fakeUnitsStart -= j
				s.unitsStart -= n
				return s.unitsStart
			}
			return 0
		}
		if s.freeList[i] != 0 {
			break
		}
	}
	ret := s.removeNode(i)
	s.splitBlock(ret, i, indx)
	return ret
}

// allocUnits 分配 NU 个单元，0 表失败。
func (s *subAlloc) allocUnits(nu int) int {
	if nu < 1 || nu > 128 {
		return 0
	}
	indx := s.units2indx[nu-1]
	if s.freeList[indx] != 0 {
		return s.removeNode(indx)
	}
	ret := s.loUnit
	s.loUnit += u2b(s.indx2units[indx])
	if s.loUnit <= s.hiUnit {
		return ret
	}
	s.loUnit -= u2b(s.indx2units[indx])
	return s.allocUnitsRare(indx)
}

// allocContext 从顶部向下分配上下文。
func (s *subAlloc) allocContext() int {
	if s.hiUnit != s.loUnit {
		s.hiUnit -= unitSize
		return s.hiUnit
	}
	if s.freeList[0] != 0 {
		return s.removeNode(0)
	}
	return s.allocUnitsRare(0)
}

// expandUnits 扩展块，0 表失败。
func (s *subAlloc) expandUnits(oldPtr, oldNU int) int {
	if oldNU+1 > 128 {
		return 0
	}
	i0 := s.units2indx[oldNU-1]
	i1 := s.units2indx[oldNU]
	if i0 == i1 {
		return oldPtr
	}
	ptr := s.allocUnits(oldNU + 1)
	if ptr != 0 {
		copy(s.heap[ptr:ptr+u2b(oldNU)], s.heap[oldPtr:oldPtr+u2b(oldNU)])
		s.insertNode(oldPtr, i0)
	}
	return ptr
}

// shrinkUnits 收缩块。
func (s *subAlloc) shrinkUnits(oldPtr, oldNU, newNU int) int {
	i0 := s.units2indx[oldNU-1]
	i1 := s.units2indx[newNU-1]
	if i0 == i1 {
		return oldPtr
	}
	if s.freeList[i1] != 0 {
		ptr := s.removeNode(i1)
		copy(s.heap[ptr:ptr+u2b(newNU)], s.heap[oldPtr:oldPtr+u2b(newNU)])
		s.insertNode(oldPtr, i0)
		return ptr
	}
	s.splitBlock(oldPtr, i0, i1)
	return oldPtr
}

// freeUnits 释放块。
func (s *subAlloc) freeUnits(ptr, oldNU int) {
	s.insertNode(ptr, s.units2indx[oldNU-1])
}
