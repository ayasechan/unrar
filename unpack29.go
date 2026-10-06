package rar

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ayasechan/unrar/internal/bitio"
	"github.com/ayasechan/unrar/internal/huff"
	"github.com/ayasechan/unrar/internal/ppm"
	"github.com/ayasechan/unrar/internal/rarvm"
)

// RAR 2.9+（UNP_VER 29）解包器。单遍流式：窗口 + 表状态常驻，
// 每文件用独立位流（pack 段）驱动；固实链复用同一解包器。
const (
	nc30            = 299
	dc30            = 60
	ldc30           = 17
	rc30            = 28
	bc30            = 20
	bc20bc          = 20
	huffTableSize30 = nc30 + dc30 + rc30 + ldc30
	max3IncLZMatch  = 0x101 + 3
	lowDistRepCount = 16
	minWindow       = 0x40000
	maxWindow4      = 8 << 20

	blockLZ  = 0
	blockPPM = 1
)

var (
	lDecode       = [...]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224}
	lBits         = [...]byte{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5}
	sDDecode      = [...]byte{0, 4, 8, 16, 32, 64, 128, 192}
	sDBits        = [...]byte{2, 2, 3, 4, 5, 6, 6, 6}
	dBitLenCounts = [...]int{4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12}
)

var (
	dDecode [dc30]uint
	dBits   [dc30]uint
)

func init() {
	dist, bitLen, slot := 0, 0, 0
	for _, c := range dBitLenCounts {
		for j := 0; j < c; j++ {
			dDecode[slot] = uint(dist)
			dBits[slot] = uint(bitLen)
			slot++
			dist += 1 << uint(bitLen)
		}
		bitLen++
	}
}

type blockTables30 struct {
	ld, dd, ldd, rd, bd *huff.Table
}

// unpack29 是 v29 解包器。
type unpack29 struct {
	lzWindow
	prevLowDist uint64
	lowDistRep  int
	tables      blockTables30
	oldTable    []byte
	tablesRead  bool
	blockType   int
	ppmEsc      int
	ppm         *ppm.PPM
	destSize    int64 // -1 表示未知
	written     int64
	out         io.Writer
	werr        error // 输出错误（读端提前关闭），置位后停机
	sticky      error // 需外部阶段处理的哨兵
	vm          rarvm.VM
	filters     []*filter30
	prgStack    []*filter30
	oldLens     []uint64
	lastFilter  uint64
}

// filter30 是 v29 过滤器（对齐 UnpackFilter30）。
type filter30 struct {
	blockStart  uint64
	blockLength uint64
	nextWindow  bool
	parent      int
	prg         rarvm.Program
}

// maxUnpackFilters 是过滤器数量上限。
const maxUnpackFilters = 8192

// init 初始化解包器。chain 表示固实链续接（保留窗口与表）。
func (u *unpack29) init(winSize uint64, chain bool) error {
	if winSize < minWindow {
		winSize = minWindow
	}
	if winSize > maxWindow4 {
		return fmt.Errorf("%w: RAR4 dictionary %d", ErrUnsupported, winSize)
	}
	if !chain || u.win == nil || u.winSize != winSize {
		u.resetFresh(winSize)
		u.tables = blockTables30{}
		u.oldTable = make([]byte, huffTableSize30)
		u.tablesRead = false
		u.blockType = blockLZ
		u.ppmEsc = 2
	}
	u.initFilters30(chain)
	u.destSize = -1
	u.written = 0
	return nil
}

// initFilters30 重置过滤器栈；非链首保留已登记过滤器。
func (u *unpack29) initFilters30(chain bool) {
	if !chain {
		u.filters = nil
		u.oldLens = nil
		u.lastFilter = 0
	}
	u.prgStack = nil
}

// decode 解一个文件的 pack 流到 out。
func (u *unpack29) decode(br *bitio.Reader, out io.Writer, destSize int64) error {
	u.out = out
	u.destSize = destSize
	u.written = 0
	u.werr = nil
	u.sticky = nil
	if !br.Refill() {
		return nil
	}
	if !u.tablesRead {
		ok, err := u.readTables(br)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}
	for {
		if u.werr != nil {
			return u.werr
		}
		u.unpPtr %= u.winSize
		if u.prevPtr > u.unpPtr {
			u.firstWinDone = true
		}
		u.prevPtr = u.unpPtr
		if br.NeedRefill() {
			if !br.Refill() {
				break
			}
		}
		if (u.wrPtr-u.unpPtr)%u.winSize <= max3IncLZMatch && u.wrPtr != u.unpPtr {
			u.writeBuf30()
			if u.werr != nil {
				return u.werr
			}
			if u.destSize >= 0 && u.written > u.destSize {
				return nil
			}
		}
		if u.blockType == blockPPM {
			done, err := u.stepPPM(br)
			if err != nil {
				return err
			}
			if done {
				u.writeBuf30()
				if u.werr != nil {
					return u.werr
				}
				return nil
			}
			continue
		}
		num := u.tables.ld.Decode(br)
		switch {
		case num < 256:
			u.win[u.unpPtr] = byte(num)
			u.unpPtr++
		case num >= 271:
			u.decodeLong(br, num)
		case num == 256:
			if !u.readEndOfBlock(br) {
				u.writeBuf30()
				if u.werr != nil {
					return u.werr
				}
				return u.sticky
			}
		case num == 257:
			if !u.readVMCode(br) {
				u.writeBuf30()
				if u.werr != nil {
					return u.werr
				}
				return u.sticky
			}
		case num == 258:
			if u.lastLength != 0 {
				u.copyString(u.lastLength, u.oldDist[0])
			}
		case num < 263:
			d := num - 259
			dist := u.oldDist[d]
			for i := d; i > 0; i-- {
				u.oldDist[i] = u.oldDist[i-1]
			}
			u.oldDist[0] = dist
			ln := u.tables.rd.Decode(br)
			length := uint64(lDecode[ln]) + 2
			if b := lBits[ln]; b > 0 {
				length += uint64(br.GetBits()) >> (16 - b)
				br.AddBits(uint(b))
			}
			u.lastLength = length
			u.copyString(length, dist)
		default: // 263..270
			idx := num - 263
			dist := uint64(sDDecode[idx]) + 1
			if b := sDBits[idx]; b > 0 {
				dist += uint64(br.GetBits()) >> (16 - b)
				br.AddBits(uint(b))
			}
			u.insertOldDist(dist)
			u.lastLength = 2
			u.copyString(2, dist)
		}
	}
	u.writeBuf30()
	if u.werr != nil {
		return u.werr
	}
	return nil
}

// decodeLong 处理 271+ 长匹配。
func (u *unpack29) decodeLong(br *bitio.Reader, num uint) {
	idx := num - 271
	length := uint64(lDecode[idx]) + 3
	if b := lBits[idx]; b > 0 {
		length += uint64(br.GetBits()) >> (16 - b)
		br.AddBits(uint(b))
	}
	distNum := u.tables.dd.Decode(br)
	dist := uint64(dDecode[distNum]) + 1
	if b := dBits[distNum]; b > 0 {
		if distNum > 9 {
			if b > 4 {
				dist += (uint64(br.GetBits()) >> (20 - b)) << 4
				br.AddBits(b - 4)
			}
			if u.lowDistRep > 0 {
				u.lowDistRep--
				dist += u.prevLowDist
			} else {
				low := u.tables.ldd.Decode(br)
				if low == 16 {
					u.lowDistRep = lowDistRepCount - 1
					dist += u.prevLowDist
				} else {
					dist += uint64(low)
					u.prevLowDist = uint64(low)
				}
			}
		} else {
			dist += uint64(br.GetBits()) >> (16 - b)
			br.AddBits(b)
		}
	}
	if dist >= 0x2000 {
		length++
		if dist >= 0x40000 {
			length++
		}
	}
	u.insertOldDist(dist)
	u.lastLength = length
	u.copyString(length, dist)
}

// writeBuf30 把 WrPtr..UnpPtr 落盘，途中执行命中的过滤器。
func (u *unpack29) writeBuf30() {
	writtenBorder := u.wrPtr
	writeSize := (u.unpPtr - writtenBorder) % u.winSize
	for i := 0; i < len(u.prgStack); i++ {
		flt := u.prgStack[i]
		if flt == nil {
			continue
		}
		if flt.nextWindow {
			flt.nextWindow = false
			continue
		}
		bs, bl := flt.blockStart, flt.blockLength
		if (bs-writtenBorder)%u.winSize < writeSize {
			if writtenBorder != bs {
				u.writeArea(writtenBorder, bs)
				writtenBorder = bs
				writeSize = (u.unpPtr - writtenBorder) % u.winSize
			}
			if bl <= writeSize {
				blockEnd := (bs + bl) % u.winSize
				u.vm.SetMemory(0, u.windowSlice(bs, bl))
				u.executeCode(&flt.prg)
				fd, fsize := flt.prg.Filtered()
				u.prgStack[i] = nil
				for i+1 < len(u.prgStack) {
					next := u.prgStack[i+1]
					if next == nil || next.blockStart != bs ||
						next.blockLength != uint64(fsize) || next.nextWindow {
						break
					}
					u.vm.SetMemory(0, fd[:fsize])
					u.executeCode(&next.prg)
					fd, fsize = next.prg.Filtered()
					i++
					u.prgStack[i] = nil
				}
				u.writeFiltered(fd[:fsize])
				writtenBorder = blockEnd
				writeSize = (u.unpPtr - writtenBorder) % u.winSize
			} else {
				for j := i; j < len(u.prgStack); j++ {
					if f := u.prgStack[j]; f != nil && f.nextWindow {
						f.nextWindow = false
					}
				}
				u.wrPtr = writtenBorder
				return
			}
		}
	}
	u.writeArea(writtenBorder, u.unpPtr)
	u.wrPtr = u.unpPtr
}

// windowSlice 取窗口环形段（跨越尾部时拷贝拼接）。
func (u *unpack29) windowSlice(off, n uint64) []byte {
	if n == 0 {
		return nil
	}
	if off+n <= u.winSize {
		return u.win[off : off+n]
	}
	out := make([]byte, 0, n)
	out = append(out, u.win[off:]...)
	out = append(out, u.win[:n-(u.winSize-off)]...)
	return out
}

// executeCode 运行过滤器（InitR[6] 置已写字节）。
func (u *unpack29) executeCode(prg *rarvm.Program) {
	prg.InitR[6] = uint32(u.written)
	u.vm.Execute(prg)
}

// writeFiltered 输出过滤后数据（按 DestUnpSize 截断，计数不截）。
func (u *unpack29) writeFiltered(data []byte) {
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

// readVMCode 从流读过滤器程序。
func (u *unpack29) readVMCode(br *bitio.Reader) bool {
	first := uint32(br.GetBits()) >> 8
	br.AddBits(8)
	length := (first & 7) + 1
	if length == 7 {
		length = uint32(br.GetBits()>>8) + 7
		br.AddBits(8)
	} else if length == 8 {
		length = uint32(br.GetBits())
		br.AddBits(16)
	}
	if length == 0 {
		return false
	}
	code := make([]byte, length)
	for i := range code {
		if br.InAddr >= br.ReadTop-1 && !br.Refill() && i < len(code)-1 {
			return false
		}
		code[i] = byte(br.GetBits() >> 8)
		br.AddBits(8)
	}
	return u.addVMCode(first, code)
}

// addVMCode 登记过滤器（对齐 AddVMCode）。
func (u *unpack29) addVMCode(first uint32, code []byte) bool {
	u.vm.Init()
	vmIn := bitio.NewReader(bytes.NewReader(code))
	// 预读全部，让 InAddr/ReadTop 可用。
	vmIn.Refill()
	var filtPos uint64
	if first&0x80 != 0 {
		filtPos = uint64(rarvm.ReadData(vmIn))
		if filtPos == 0 {
			u.initFilters30(false)
		} else {
			filtPos--
		}
	} else {
		filtPos = u.lastFilter
	}
	if filtPos > uint64(len(u.filters)) || filtPos > uint64(len(u.oldLens)) {
		return false
	}
	u.lastFilter = filtPos
	newFilter := filtPos == uint64(len(u.filters))
	stackFilter := &filter30{}
	var filter *filter30
	if newFilter {
		if filtPos > maxUnpackFilters {
			return false
		}
		stackFilter.parent = len(u.filters)
		filter = &filter30{}
		u.filters = append(u.filters, filter)
		u.oldLens = append(u.oldLens, 0)
	} else {
		filter = u.filters[filtPos]
		stackFilter.parent = int(filtPos)
	}
	// 压缩 PrgStack 空洞。
	w := 0
	for _, f := range u.prgStack {
		if f != nil {
			u.prgStack[w] = f
			w++
		}
	}
	for i := w; i < len(u.prgStack); i++ {
		u.prgStack[i] = nil
	}
	empty := len(u.prgStack) - w
	if empty == 0 {
		if len(u.prgStack) > maxUnpackFilters {
			return false
		}
		u.prgStack = append(u.prgStack, nil)
		empty = 1
	}
	u.prgStack[len(u.prgStack)-empty] = stackFilter
	blockStart := uint64(rarvm.ReadData(vmIn))
	if first&0x40 != 0 {
		blockStart += 258
	}
	stackFilter.blockStart = (blockStart + u.unpPtr) % u.winSize
	if first&0x20 != 0 {
		stackFilter.blockLength = uint64(rarvm.ReadData(vmIn))
		u.oldLens[filtPos] = stackFilter.blockLength
	} else if filtPos < uint64(len(u.oldLens)) {
		stackFilter.blockLength = u.oldLens[filtPos]
	}
	stackFilter.nextWindow = u.wrPtr != u.unpPtr && (u.wrPtr-u.unpPtr)%u.winSize <= blockStart
	stackFilter.prg.InitR[4] = uint32(stackFilter.blockLength)
	if first&0x10 != 0 {
		initMask := uint32(vmIn.GetBits()) >> 9
		vmIn.AddBits(7)
		for i := uint32(0); i < 7; i++ {
			if initMask&(1<<i) != 0 {
				stackFilter.prg.InitR[i] = rarvm.ReadData(vmIn)
			}
		}
	}
	if newFilter {
		vmCodeSize := uint64(rarvm.ReadData(vmIn))
		if vmCodeSize >= 0x10000 || vmCodeSize == 0 || uint64(vmIn.InAddr)+vmCodeSize > uint64(len(code)) {
			return false
		}
		vmCode := make([]byte, vmCodeSize)
		for i := range vmCode {
			// C++ 在此循环内无越界检查（32KB 零垫缓冲兜底），
			// 仅保证当前字节存在，尾部按零读出。
			if vmIn.InAddr >= len(code) {
				return false
			}
			vmCode[i] = byte(vmIn.GetBits() >> 8)
			vmIn.AddBits(8)
		}
		u.vm.Prepare(vmCode, &filter.prg)
	}
	stackFilter.prg.Type = filter.prg.Type
	return true
}

func (u *unpack29) writeArea(start, end uint64) {
	if end < start {
		u.writeBytes(start, u.winSize-start)
		u.writeBytes(0, end)
		return
	}
	u.writeBytes(start, end-start)
}

func (u *unpack29) writeBytes(off, n uint64) {
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

// readEndOfBlock 处理 256：false 表示本文件结束。
func (u *unpack29) readEndOfBlock(br *bitio.Reader) bool {
	field := br.GetBits()
	var newTable, newFile bool
	if field&0x8000 != 0 {
		newTable = true
		br.AddBits(1)
	} else {
		newFile = true
		newTable = field&0x4000 != 0
		br.AddBits(2)
	}
	u.tablesRead = !newTable
	if newFile {
		return false
	}
	ok, err := u.readTables(br)
	if err != nil {
		u.sticky = err
		return false
	}
	return ok
}

// readTables 读取 Huffman 表；PPM 块就地初始化模型后继续。
func (u *unpack29) readTables(br *bitio.Reader) (bool, error) {
	if br.InAddr > br.ReadTop-25 {
		if !br.Refill() {
			return false, nil
		}
	}
	br.AddBits((8 - br.InBit) & 7)
	field := br.GetBits()
	if field&0x8000 != 0 {
		u.blockType = blockPPM
		if u.ppm == nil {
			u.ppm = &ppm.PPM{}
		}
		getByte := func() byte { return br.GetByte() }
		if !u.ppm.DecodeInit(getByte, &u.ppmEsc) {
			return false, nil
		}
		return true, nil
	}
	u.blockType = blockLZ
	u.prevLowDist = 0
	u.lowDistRep = 0
	if field&0x4000 == 0 {
		for i := range u.oldTable {
			u.oldTable[i] = 0
		}
	}
	br.AddBits(2)
	var bitLen [bc20bc]byte
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
	u.tables.bd = huff.MakeTables(bitLen[:], bc30)
	table := make([]byte, huffTableSize30)
	for i := 0; i < len(table); {
		if br.NeedRefillSmall() {
			if !br.Refill() {
				return false, nil
			}
		}
		num := u.tables.bd.Decode(br)
		switch {
		case num < 16:
			table[i] = (byte(num) + u.oldTable[i]) & 0xf
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
				return false, nil
			}
			for n > 0 && i < len(table) {
				table[i] = table[i-1]
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
			for n > 0 && i < len(table) {
				table[i] = 0
				i++
				n--
			}
		}
	}
	u.tablesRead = true
	if br.Overrun() {
		return false, nil
	}
	u.tables.ld = huff.MakeTables(table[0:nc30], nc30)
	u.tables.dd = huff.MakeTables(table[nc30:nc30+dc30], dc30)
	u.tables.ldd = huff.MakeTables(table[nc30+dc30:nc30+dc30+ldc30], ldc30)
	u.tables.rd = huff.MakeTables(table[nc30+dc30+ldc30:], rc30)
	copy(u.oldTable, table)
	return true, nil
}

// safePPM 解一个 PPM 字符，损坏时复位模型并切回 LZ。
func (u *unpack29) safePPM() int {
	ch := u.ppm.DecodeChar()
	if ch == -1 {
		u.ppm.CleanUp()
		u.blockType = blockLZ
	}
	return ch
}

// stepPPM 执行一步 PPM 解码；done 表本文件结束。
func (u *unpack29) stepPPM(br *bitio.Reader) (bool, error) {
	ch := u.ppm.DecodeChar()
	if ch == -1 {
		u.ppm.CleanUp()
		u.blockType = blockLZ
		return true, nil
	}
	if ch == u.ppmEsc {
		next := u.safePPM()
		switch next {
		case 0: // PPM 编码结束，重读表。
			ok, err := u.readTables(br)
			if err != nil {
				return true, err
			}
			if !ok {
				return true, nil
			}
			return false, nil
		case -1: // 损坏。
			return true, nil
		case 2: // 文件结束。
			return true, nil
		case 3: // 读 VM 码。
			if !u.readVMCodePPM() {
				return true, nil
			}
			return false, nil
		case 4: // PPM 内嵌 LZ。
			var dist uint32
			var length byte
			failed := false
			for i := 0; i < 4; i++ {
				c := u.safePPM()
				if c == -1 {
					failed = true
					break
				}
				if i == 3 {
					length = byte(c)
				} else {
					dist = (dist << 8) | uint32(byte(c))
				}
			}
			if failed {
				return true, nil
			}
			u.copyString(uint64(length)+32, uint64(dist)+2)
			return false, nil
		case 5: // 单字节距离 RLE。
			l := u.safePPM()
			if l == -1 {
				return true, nil
			}
			u.copyString(uint64(l)+4, 1)
			return false, nil
		}
		// next == 1：当前字节即 escape 本身，落盘。
	}
	u.win[u.unpPtr] = byte(ch)
	u.unpPtr++
	return false, nil
}

// readVMCodePPM 从 PPM 流读过滤器程序。
func (u *unpack29) readVMCodePPM() bool {
	first := u.safePPM()
	if first == -1 {
		return false
	}
	length := (uint32(first) & 7) + 1
	if length == 7 {
		b1 := u.safePPM()
		if b1 == -1 {
			return false
		}
		length = uint32(b1) + 7
	} else if length == 8 {
		b1 := u.safePPM()
		if b1 == -1 {
			return false
		}
		b2 := u.safePPM()
		if b2 == -1 {
			return false
		}
		length = uint32(b1)*256 + uint32(b2)
	}
	if length == 0 {
		return false
	}
	code := make([]byte, length)
	for i := range code {
		ch := u.safePPM()
		if ch == -1 {
			return false
		}
		code[i] = byte(ch)
	}
	return u.addVMCode(uint32(first), code)
}
