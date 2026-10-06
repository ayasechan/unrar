package rar

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ayasechan/unrar/internal/bitio"
	"github.com/ayasechan/unrar/internal/huff"
)

// RAR5（UNP_VER 0，对应 VER_PACK5）解包器。
const (
	nc5       = 306
	dcb5      = 64
	dcx5      = 80
	ldc5      = 16
	rc5       = 44
	bc5       = 20
	huffSizeB = nc5 + dcb5 + rc5 + ldc5
	huffSizeX = nc5 + dcx5 + rc5 + ldc5

	maxIncLZMatch5    = 0x1001 + 3
	maxFilterBlock    = 0x400000
	maxUnpackFilters5 = 8192
	maxWrite5         = 0x400000
	maxWindow5        = 1 << 30 // RAR5 字典实现上限 1GB（协议可更大，超限拒绝）。
)

// RAR5 过滤器类型（对齐 FilterType）。
const (
	filterDelta5 = 0
	filterE85    = 1
	filterE8E95  = 2
	filterARM5   = 3
	filterNone5  = 10
)

type blockTables5 struct {
	ld, dd, ldd, rd, bd *huff.Table
}

// blockHead5 是 RAR5 压缩块头。
type blockHead5 struct {
	size    int
	bitSize int
	start   int
	last    bool
	table   bool
}

// filter5 是 RAR5 过滤器（对齐 UnpackFilter）。
type filter5 struct {
	typ        uint
	channels   uint
	nextWindow bool
	start      uint64
	length     uint64
}

// unpack50 是 v50 解包器。
type unpack50 struct {
	lzWindow
	tables     blockTables5
	tablesRead bool
	extraDist  bool
	block      blockHead5
	border     int
	filters    []filter5
	destSize   int64
	written    int64
	out        io.Writer
	werr       error
	scratch    []byte // copyBlock 复用缓冲（仅 writeBuf 内有效）。
	deltaBuf   []byte // Delta 输出复用缓冲（仅 writeBuf 内有效）。
}

// init 初始化解包器。chain 表示固实链续接。
func (u *unpack50) init(winSize uint64, chain bool, extraDist bool) error {
	if winSize < minWindow {
		winSize = minWindow
	}
	if winSize > maxWindow5 {
		return fmt.Errorf("%w: RAR5 dictionary %d", ErrUnsupported, winSize)
	}
	u.extraDist = extraDist
	if !chain || u.win == nil || u.winSize != winSize {
		u.resetFresh(winSize)
		u.tables = blockTables5{}
		u.tablesRead = false
	}
	u.filters = nil
	u.block.size = -1
	u.block.start = 0
	u.destSize = -1
	u.written = 0
	u.werr = nil
	return nil
}

// refill 续流并维护块记账（对齐 UnpReadBuf）。
func (u *unpack50) refill(br *bitio.Reader) bool {
	if br.ReadTop-br.InAddr < 0 {
		return false
	}
	u.block.size -= br.InAddr - u.block.start
	if !br.Refill() {
		return false
	}
	u.block.start = br.InAddr
	u.border = br.ReadTop - 30
	if u.block.size != -1 {
		if s := u.block.start + u.block.size - 1; s < u.border {
			u.border = s
		}
	}
	return true
}

// decode 解一个文件的 pack 流到 out。
func (u *unpack50) decode(br *bitio.Reader, out io.Writer, destSize int64) error {
	u.out = out
	u.destSize = destSize
	u.written = 0
	u.werr = nil
	if !u.refill(br) {
		return nil
	}
	if !u.readBlockHeader(br) || !u.readTables(br) || !u.tablesRead {
		return nil
	}
loop:
	for {
		if u.unpPtr >= u.winSize {
			u.unpPtr -= u.winSize
		}
		if u.prevPtr > u.unpPtr {
			u.firstWinDone = true
		}
		u.prevPtr = u.unpPtr
		if br.InAddr >= u.border {
			fileDone := false
			for br.InAddr > u.block.start+u.block.size-1 ||
				(br.InAddr == u.block.start+u.block.size-1 && int(br.InBit) >= u.block.bitSize) {
				if u.block.last {
					fileDone = true
					break
				}
				if !u.readBlockHeader(br) || !u.readTables(br) {
					return nil
				}
			}
			if fileDone || !u.refill(br) {
				break
			}
		}
		if u.writeBorder != u.unpPtr && (u.writeBorder-u.unpPtr)%u.winSize <= maxIncLZMatch5 {
			u.writeBuf()
			if u.werr != nil {
				return u.werr
			}
			if u.destSize >= 0 && u.written > u.destSize {
				return nil
			}
		}
		slot := u.tables.ld.Decode(br)
		switch {
		case slot < 256:
			u.win[u.unpPtr] = byte(slot)
			u.unpPtr++
		case slot >= 262:
			u.decodeLong(br, slot)
		case slot >= 258: // 258..261（<256、>=262 已排除）
			d := slot - 258
			dist := u.oldDist[d]
			for i := d; i > 0; i-- {
				u.oldDist[i] = u.oldDist[i-1]
			}
			u.oldDist[0] = dist
			ln := u.tables.rd.Decode(br)
			length := slotToLength(br, ln)
			u.lastLength = length
			u.copyString(length, dist)
		case slot == 257:
			if u.lastLength != 0 {
				u.copyString(u.lastLength, u.oldDist[0])
			}
		case slot == 256:
			var flt filter5
			if !u.readFilter(br, &flt) || !u.addFilter(flt) {
				break loop
			}
		}
		if u.werr != nil {
			return u.werr
		}
	}
	u.writeBuf()
	return u.werr
}

// decodeLong 处理 262+ 长匹配。
func (u *unpack50) decodeLong(br *bitio.Reader, slot uint) {
	length := slotToLength(br, slot-262)
	var dist uint64 = 1
	distSlot := u.tables.dd.Decode(br)
	var dbits uint
	if distSlot < 4 {
		dist += uint64(distSlot)
	} else {
		dbits = distSlot/2 - 1
		dist += uint64(2|(distSlot&1)) << dbits
	}
	if dbits > 0 {
		if dbits >= 4 {
			if dbits > 4 {
				if dbits > 36 {
					dist += (br.GetBits64() >> (68 - dbits)) << 4
				} else {
					dist += uint64(br.GetBits32()>>(36-dbits)) << 4
				}
				br.AddBits(dbits - 4)
			}
			low := u.tables.ldd.Decode(br)
			dist += uint64(low)
		} else {
			dist += uint64(br.GetBits()) >> (16 - dbits)
			br.AddBits(dbits)
		}
	}
	if dist > 0x100 {
		length++
		if dist > 0x2000 {
			length++
			if dist > 0x40000 {
				length++
			}
		}
	}
	u.insertOldDist(dist)
	u.lastLength = length
	u.copyString(length, dist)
}

// slotToLength 由槽位解长度（v29/v50 共用）。
func slotToLength(br *bitio.Reader, slot uint) uint64 {
	if slot < 8 {
		return uint64(slot) + 2
	}
	var lbits uint
	length := uint64(2)
	lbits = slot/4 - 1
	length += uint64(4|(slot&3)) << lbits
	if lbits > 0 {
		length += uint64(br.GetBits()) >> (16 - lbits)
		br.AddBits(lbits)
	}
	return length
}

// readBlockHeader 读压缩块头。
func (u *unpack50) readBlockHeader(br *bitio.Reader) bool {
	if br.InAddr > br.ReadTop-7 {
		if !u.refill(br) {
			return false
		}
	}
	br.AddBits((8 - br.InBit) & 7)
	flags := br.GetBits() >> 8
	br.AddBits(8)
	byteCount := ((flags >> 3) & 3) + 1
	if byteCount == 4 {
		return false
	}
	u.block.bitSize = int(flags&7) + 1
	saved := br.GetBits() >> 8
	br.AddBits(8)
	size := 0
	for i := uint(0); i < uint(byteCount); i++ {
		size += int(br.GetBits()>>8) << (i * 8)
		br.AddBits(8)
	}
	u.block.size = size
	check := byte(uint32(0x5a) ^ uint32(flags) ^ uint32(size) ^ uint32(size>>8) ^ uint32(size>>16))
	if check != byte(saved) {
		return false
	}
	u.block.start = br.InAddr
	if s := u.block.start + u.block.size - 1; s < u.border {
		u.border = s
	}
	u.block.last = flags&0x40 != 0
	u.block.table = flags&0x80 != 0
	return true
}

// readTables 读 Huffman 表。
func (u *unpack50) readTables(br *bitio.Reader) bool {
	if !u.block.table {
		return true
	}
	if br.InAddr > br.ReadTop-25 {
		if !u.refill(br) {
			return false
		}
	}
	var bitLen [bc5]byte
	for i := 0; i < len(bitLen); i++ {
		l := byte(br.GetBits() >> 12)
		br.AddBits(4)
		if l == 15 {
			z := byte(br.GetBits() >> 12)
			br.AddBits(4)
			if z == 0 {
				bitLen[i] = 15
			} else {
				z += 2
				for z > 0 && i < len(bitLen) {
					bitLen[i] = 0
					i++
					z--
				}
				i--
			}
		} else {
			bitLen[i] = l
		}
	}
	u.tables.bd = huff.MakeTables(bitLen[:], bc5)
	tableSize := huffSizeB
	if u.extraDist {
		tableSize = huffSizeX
	}
	var tmp [huffSizeX]byte
	table := tmp[:tableSize]
	for i := 0; i < len(table); {
		if br.InAddr > br.ReadTop-5 {
			if !u.refill(br) {
				return false
			}
		}
		num := u.tables.bd.Decode(br)
		switch {
		case num < 16:
			table[i] = byte(num)
			i++
		case num < 18:
			var n uint
			if num == 16 {
				n = uint(br.GetBits()>>13) + 3
				br.AddBits(3)
			} else {
				n = uint(br.GetBits()>>9) + 11
				br.AddBits(7)
			}
			if i == 0 {
				return false
			}
			prev := table[i-1]
			for n > 0 && i < len(table) {
				table[i] = prev
				i++
				n--
			}
		default:
			var n uint
			if num == 18 {
				n = uint(br.GetBits()>>13) + 3
				br.AddBits(3)
			} else {
				n = uint(br.GetBits()>>9) + 11
				br.AddBits(7)
			}
			m := int(n)
			if m > len(table)-i {
				m = len(table) - i
			}
			clear(table[i : i+m])
			i += m
		}
	}
	u.tablesRead = true
	if br.InAddr > br.ReadTop {
		return false
	}
	dcodes := dcb5
	if u.extraDist {
		dcodes = dcx5
	}
	u.tables.ld = huff.MakeTables(table[0:nc5], nc5)
	u.tables.dd = huff.MakeTables(table[nc5:nc5+dcodes], dcodes)
	u.tables.ldd = huff.MakeTables(table[nc5+dcodes:nc5+dcodes+ldc5], ldc5)
	u.tables.rd = huff.MakeTables(table[nc5+dcodes+ldc5:], rc5)
	return true
}

// readFilterData 读过滤器变长整数。
func readFilterData(br *bitio.Reader) uint64 {
	n := uint64(br.GetBits()>>14) + 1
	br.AddBits(2)
	var data uint64
	for i := uint64(0); i < n; i++ {
		data += uint64(br.GetBits()>>8) << (i * 8)
		br.AddBits(8)
	}
	return data
}

// readFilter 读过滤器描述。
func (u *unpack50) readFilter(br *bitio.Reader, flt *filter5) bool {
	if br.InAddr > br.ReadTop-16 {
		if !u.refill(br) {
			return false
		}
	}
	flt.start = readFilterData(br)
	flt.length = readFilterData(br)
	if flt.length > maxFilterBlock {
		flt.length = 0
	}
	flt.typ = uint(br.GetBits() >> 13)
	br.AddBits(3)
	if flt.typ == filterDelta5 {
		flt.channels = uint(br.GetBits()>>11) + 1
		br.AddBits(5)
	}
	flt.nextWindow = false
	return true
}

// addFilter 登记过滤器。
func (u *unpack50) addFilter(flt filter5) bool {
	if len(u.filters) >= maxUnpackFilters5 {
		u.writeBuf()
		if len(u.filters) >= maxUnpackFilters5 {
			u.filters = nil
		}
	}
	flt.nextWindow = u.wrPtr != u.unpPtr && (u.wrPtr-u.unpPtr)%u.winSize <= flt.start
	flt.start = (flt.start + u.unpPtr) % u.winSize
	u.filters = append(u.filters, flt)
	return true
}

// writeBuf 落盘并执行命中的过滤器。
func (u *unpack50) writeBuf() {
	writtenBorder := u.wrPtr
	fullWrite := (u.unpPtr - writtenBorder) % u.winSize
	writeLeft := fullWrite
	notAll := false
	for i := 0; i < len(u.filters); i++ {
		flt := &u.filters[i]
		if flt.typ == filterNone5 {
			continue
		}
		if flt.nextWindow {
			if (flt.start-u.wrPtr)%u.winSize <= fullWrite {
				flt.nextWindow = false
			}
			continue
		}
		bs, bl := flt.start, flt.length
		if (bs-writtenBorder)%u.winSize < writeLeft {
			if writtenBorder != bs {
				u.writeArea(writtenBorder, bs)
				writtenBorder = bs
				writeLeft = (u.unpPtr - writtenBorder) % u.winSize
			}
			if bl <= writeLeft {
				if bl > 0 {
					blockEnd := (bs + bl) % u.winSize
					mem := u.copyBlock(bs, bl)
					out := u.applyFilter(mem, flt)
					flt.typ = filterNone5
					if out != nil {
						u.writeFiltered(out)
					}
					writtenBorder = blockEnd
					writeLeft = (u.unpPtr - writtenBorder) % u.winSize
				}
			} else {
				u.wrPtr = writtenBorder
				for j := i; j < len(u.filters); j++ {
					if u.filters[j].typ != filterNone5 {
						u.filters[j].nextWindow = false
					}
				}
				notAll = true
				break
			}
		}
	}
	// 移除已处理过滤器。
	w := 0
	for _, f := range u.filters {
		if f.typ != filterNone5 {
			u.filters[w] = f
			w++
		}
	}
	u.filters = u.filters[:w]
	if !notAll {
		u.writeArea(writtenBorder, u.unpPtr)
		u.wrPtr = u.unpPtr
	}
	// 4MB 写边界。
	m := u.winSize
	if maxWrite5 < m {
		m = maxWrite5
	}
	u.writeBorder = (u.unpPtr + m) % u.winSize
	if u.writeBorder == u.unpPtr ||
		u.wrPtr != u.unpPtr && (u.wrPtr-u.unpPtr)%u.winSize < (u.writeBorder-u.unpPtr)%u.winSize {
		u.writeBorder = u.wrPtr
	}
}

// copyBlock 拷贝窗口环形段（过滤器输入恒拷贝，缓冲复用）。
func (u *unpack50) copyBlock(off, n uint64) []byte {
	if uint64(cap(u.scratch)) < n {
		u.scratch = make([]byte, n)
	}
	out := u.scratch[:n]
	if off+n <= u.winSize {
		copy(out, u.win[off:off+n])
		return out
	}
	k := copy(out, u.win[off:])
	copy(out[k:], u.win[:n-uint64(k)])
	return out
}

// applyFilter 执行 RAR5 过滤器；未知类型返回 nil（数据按计数丢弃）。
func (u *unpack50) applyFilter(data []byte, flt *filter5) []byte {
	switch flt.typ {
	case filterE85, filterE8E95:
		const fileSize = 0x1000000
		fileOffset := uint32(u.written)
		cmp := byte(0xe8)
		if flt.typ == filterE8E95 {
			cmp = 0xe9
		}
		n := uint32(len(data))
		for pos := uint32(0); pos+4 < n; {
			cur := data[pos]
			pos++
			if cur == 0xe8 || cur == cmp {
				offset := (pos + fileOffset) % fileSize
				addr := binary.LittleEndian.Uint32(data[pos : pos+4])
				if addr&0x80000000 != 0 {
					if (addr+offset)&0x80000000 == 0 {
						binary.LittleEndian.PutUint32(data[pos:pos+4], addr+fileSize)
					}
				} else if (addr-fileSize)&0x80000000 != 0 {
					binary.LittleEndian.PutUint32(data[pos:pos+4], addr-offset)
				}
				pos += 4
			}
		}
		return data
	case filterARM5:
		fileOffset := uint32(u.written)
		n := uint32(len(data))
		for pos := uint32(0); pos+3 < n; pos += 4 {
			d := data[pos : pos+4]
			if d[3] == 0xeb {
				offset := uint32(d[0]) + uint32(d[1])*0x100 + uint32(d[2])*0x10000
				offset -= (fileOffset + pos) / 4
				d[0] = byte(offset)
				d[1] = byte(offset >> 8)
				d[2] = byte(offset >> 16)
			}
		}
		return data
	case filterDelta5:
		channels := int(flt.channels)
		n := len(data)
		if cap(u.deltaBuf) < n {
			u.deltaBuf = make([]byte, n)
		}
		out := u.deltaBuf[:n]
		src := 0
		for ch := 0; ch < channels; ch++ {
			prev := byte(0)
			for dest := ch; dest < n; dest += channels {
				prev -= data[src]
				src++
				out[dest] = prev
			}
		}
		return out
	}
	return nil
}

func (u *unpack50) writeArea(start, end uint64) {
	if end < start {
		u.writeBytes(start, u.winSize-start)
		u.writeBytes(0, end)
		return
	}
	u.writeBytes(start, end-start)
}

func (u *unpack50) writeBytes(off, n uint64) {
	if n == 0 {
		return
	}
	if u.destSize >= 0 {
		left := u.destSize - u.written
		if left <= 0 {
			u.written += int64(n)
			return
		}
		if n > uint64(left) {
			n = uint64(left)
		}
	}
	if _, err := u.out.Write(u.win[off : off+n]); err != nil && u.werr == nil {
		u.werr = err
	}
	u.written += int64(n)
}

// writeFiltered 输出过滤后数据（按 DestUnpSize 截断，计数不截）。
func (u *unpack50) writeFiltered(data []byte) {
	n := uint64(len(data))
	if n == 0 {
		return
	}
	out := data
	if u.destSize >= 0 {
		left := u.destSize - u.written
		if left <= 0 {
			u.written += int64(n)
			return
		}
		if n > uint64(left) {
			out = data[:left]
		}
	}
	if _, err := u.out.Write(out); err != nil && u.werr == nil {
		u.werr = err
	}
	u.written += int64(n)
}
