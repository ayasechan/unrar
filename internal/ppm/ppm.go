package ppm

// PPMd 阶模型解码器（解码侧）。
//
// 堆内对象全部用偏移表示（0 = 空）：
// CONTEXT = NumStats u16 + SummFreq u16 + Stats 偏移 + Suffix 偏移；
// STATE = Symbol + Freq + Successor 偏移（6 字节），
// 单状态上下文复用 Stats 槽位内联存放 OneState。

const (
	intBits     = 7
	periodBits  = 7
	totBits     = intBits + periodBits
	interval    = 1 << intBits
	binScale    = 1 << totBits
	maxFreq     = 124
	maxOrderPPM = 64

	top32 = uint32(1) << 24
	bot32 = uint32(1) << 15
)

// MaxAllocMB 限制单次 PPM arena（流内 1 字节决定，天然 ≤ 256）。
const MaxAllocMB = 256

type see2ctx struct {
	summ  uint16
	shift byte
	count byte
}

func (c *see2ctx) init(val int) {
	c.shift = periodBits - 4
	c.summ = uint16(val) << c.shift
	c.count = 4
}

func (c *see2ctx) getMean() int {
	// GET_SHORT16 为无符号动作：逻辑右移。
	ret := int(c.summ) >> c.shift
	c.summ -= uint16(ret)
	if ret == 0 {
		return 1
	}
	return ret
}

func (c *see2ctx) update() {
	if c.shift < periodBits {
		c.count--
		if c.count == 0 {
			c.summ += c.summ
			c.count = byte(3 << c.shift)
			c.shift++
		}
	}
}

type ppmState struct {
	sym  byte
	freq byte
	succ int
}

// PPM 是解码器实例。
type PPM struct {
	see2        [25][16]see2ctx
	dummy       see2ctx
	minCtx      int
	medCtx      int
	maxCtx      int
	found       int // FoundState（堆内 STATE 偏移，0 = 空）。
	numMasked   int
	initEsc     int
	orderFall   int
	maxOrder    int
	runLength   int
	initRL      int
	charMask    [256]byte
	ns2indx     [256]byte
	ns2bsindx   [256]byte
	hb2flag     [256]byte
	escCount    byte
	prevSuccess byte
	hiBitsFlag  byte
	binSumm     [128][64]uint16

	low      uint32
	code     uint32
	rng      uint32
	subLow   uint32
	subHigh  uint32
	subScale uint32
	getByte  func() byte

	sub subAlloc
}

var expEscape = [...]byte{25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2}

func getMean(summ uint16, shift, round int) int {
	return (int(summ) + (1 << (shift - round))) >> shift
}

// --- CONTEXT/STATE 访问器 ---

func (p *PPM) numStats(ctx int) int   { return int(p.sub.getU16(ctx)) }
func (p *PPM) setNumStats(ctx, v int) { p.sub.setU16(ctx, uint16(v)) }
func (p *PPM) summFreq(ctx int) int   { return int(p.sub.getU16(ctx + 2)) }
func (p *PPM) setSummFreq(ctx, v int) { p.sub.setU16(ctx+2, uint16(v)) }
func (p *PPM) addSummFreq(ctx, d int) { p.sub.setU16(ctx+2, uint16(p.summFreq(ctx)+d)) }
func (p *PPM) statsOff(ctx int) int   { return p.sub.getU32(ctx + 4) }
func (p *PPM) setStats(ctx, v int)    { p.sub.setU32(ctx+4, v) }
func (p *PPM) suffix(ctx int) int     { return p.sub.getU32(ctx + 8) }
func (p *PPM) setSuffix(ctx, v int)   { p.sub.setU32(ctx+8, v) }

func (p *PPM) readState(off int) ppmState {
	return ppmState{
		sym:  p.sub.heap[off],
		freq: p.sub.heap[off+1],
		succ: p.sub.getU32(off + 2),
	}
}

func (p *PPM) writeState(off int, st ppmState) {
	p.sub.heap[off] = st.sym
	p.sub.heap[off+1] = st.freq
	p.sub.setU32(off+2, st.succ)
}

// stateAt 取上下文第 idx 个状态的堆偏移。
func (p *PPM) stateAt(ctx, idx int) int {
	if p.numStats(ctx) == 1 {
		return oneState(ctx)
	}
	return p.statsOff(ctx) + idx*6
}

// oneState 取单状态上下文的 OneState 偏移（union 起点 +2）。
func oneState(ctx int) int { return ctx + 2 }

// --- RangeCoder ---

func (p *PPM) rcInit() {
	p.low, p.code = 0, 0
	p.rng = 0xffffffff
	for i := 0; i < 4; i++ {
		p.code = (p.code << 8) | uint32(p.getByte())
	}
}

func (p *PPM) rcNormalize() {
	for (p.low^(p.low+p.rng)) < top32 || (p.rng < bot32 && func() bool {
		p.rng = uint32(-int32(p.low)) & (bot32 - 1)
		return true
	}()) {
		p.code = (p.code << 8) | uint32(p.getByte())
		p.rng <<= 8
		p.low <<= 8
	}
}

func (p *PPM) rcCount() int {
	p.rng /= p.subScale
	return int((p.code - p.low) / p.rng)
}

func (p *PPM) rcShiftCount(shift uint) int {
	p.rng >>= shift
	return int((p.code - p.low) / p.rng)
}

func (p *PPM) rcDecode() {
	p.low += p.rng * p.subLow
	p.rng *= p.subHigh - p.subLow
}

// --- 模型管理 ---

var initBinEsc = [...]uint16{0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051}

// restartModelRare 重建空模型，false 表内存不足。
func (p *PPM) restartModelRare() bool {
	for i := range p.charMask {
		p.charMask[i] = 0
	}
	p.sub.initSubAllocator()
	if p.maxOrder < 12 {
		p.initRL = -p.maxOrder - 1
	} else {
		p.initRL = -12 - 1
	}
	p.minCtx = p.sub.allocContext()
	if p.minCtx == 0 {
		return false
	}
	p.maxCtx = p.minCtx
	p.setSuffix(p.minCtx, 0)
	p.orderFall = p.maxOrder
	p.setNumStats(p.minCtx, 256)
	p.setSummFreq(p.minCtx, 257)
	st := p.sub.allocUnits(128)
	if st == 0 {
		return false
	}
	p.setStats(p.minCtx, st)
	p.found = st
	p.runLength = p.initRL
	p.prevSuccess = 0
	for i := 0; i < 256; i++ {
		p.writeState(st+i*6, ppmState{sym: byte(i), freq: 1, succ: 0})
	}
	for i := 0; i < 128; i++ {
		for k := 0; k < 8; k++ {
			for m := 0; m < 64; m += 8 {
				p.binSumm[i][k+m] = binScale - initBinEsc[k]/uint16(i+2)
			}
		}
	}
	for i := 0; i < 25; i++ {
		for k := 0; k < 16; k++ {
			p.see2[i][k].init(5*i + 10)
		}
	}
	return true
}

// startModelRare 启动模型。
func (p *PPM) startModelRare(maxOrder int) {
	p.escCount = 1
	p.maxOrder = maxOrder
	if !p.restartModelRare() {
		return
	}
	p.ns2bsindx[0] = 0
	p.ns2bsindx[1] = 2
	for i := 2; i < 11; i++ {
		p.ns2bsindx[i] = 4
	}
	for i := 11; i < 256; i++ {
		p.ns2bsindx[i] = 6
	}
	for i := 0; i < 3; i++ {
		p.ns2indx[i] = byte(i)
	}
	m, k, step := 3, 1, 1
	for i := 3; i < 256; i++ {
		p.ns2indx[i] = byte(m)
		k--
		if k == 0 {
			step++
			k = step
			m++
		}
	}
	for i := 0; i < 0x40; i++ {
		p.hb2flag[i] = 0
	}
	for i := 0x40; i < 0x100; i++ {
		p.hb2flag[i] = 0x08
	}
	p.dummy.shift = periodBits
}

// CleanUp 数据错误后复位。
func (p *PPM) CleanUp() {
	p.sub.stopSubAllocator()
	p.sub.startSubAllocator(1)
	p.startModelRare(2)
}

// DecodeInit 初始化解码，esc 为 escape 字符（输入输出）。
func (p *PPM) DecodeInit(getByte func() byte, esc *int) bool {
	p.getByte = getByte
	maxOrder := int(getByte())
	reset := maxOrder&0x20 != 0
	var maxMB int
	if reset {
		maxMB = int(getByte())
	} else if p.sub.size == 0 {
		return false
	}
	if maxOrder&0x40 != 0 {
		*esc = int(getByte())
	}
	p.rcInit()
	if reset {
		maxOrder = (maxOrder & 0x1f) + 1
		if maxOrder > 16 {
			maxOrder = 16 + (maxOrder-16)*3
		}
		if maxOrder == 1 {
			p.sub.stopSubAllocator()
			return false
		}
		if maxMB+1 > MaxAllocMB {
			return false
		}
		p.sub.startSubAllocator(maxMB + 1)
		p.startModelRare(maxOrder)
	}
	return p.minCtx != 0
}

// inHeap 判定偏移是否在堆内（含 12 字节对象头）。
func (p *PPM) inHeap(off int) bool {
	return off > 0 && off+12 <= len(p.sub.heap)
}

// createChild 建子上下文，0 表失败。
func (p *PPM) createChild(ctx, pStats int, first ppmState) int {
	pc := p.sub.allocContext()
	if pc != 0 {
		p.setNumStats(pc, 1)
		p.writeState(oneState(pc), first)
		p.setSuffix(pc, ctx)
		s := p.readState(pStats)
		s.succ = pc
		p.writeState(pStats, s)
	}
	return pc
}

// rescale 重缩放上下文。
func (p *PPM) rescale(ctx int) {
	oldNS := p.numStats(ctx)
	stats := p.statsOff(ctx)
	foundIdx := (p.found - stats) / 6
	if foundIdx < 0 || foundIdx >= oldNS {
		foundIdx = 0 // 损坏保护：钳住而非越界。
	}
	// FoundState 下沉到首位。
	for idx := foundIdx; idx > 0; idx-- {
		a := p.readState(stats + idx*6)
		b := p.readState(stats + (idx-1)*6)
		p.writeState(stats+idx*6, b)
		p.writeState(stats+(idx-1)*6, a)
	}
	s0 := p.readState(stats)
	s0.freq += 4
	p.writeState(stats, s0)
	p.addSummFreq(ctx, 4)
	escFreq := p.summFreq(ctx) - int(s0.freq)
	adder := 0
	if p.orderFall != 0 {
		adder = 1
	}
	f := (int(s0.freq) + adder) >> 1
	s0.freq = byte(f)
	p.writeState(stats, s0)
	p.setSummFreq(ctx, f)
	i := oldNS - 1
	idx := 0
	for {
		idx++
		st := p.readState(stats + idx*6)
		escFreq -= int(st.freq)
		f = (int(st.freq) + adder) >> 1
		st.freq = byte(f)
		p.setSummFreq(ctx, p.summFreq(ctx)+f)
		if st.freq > p.readState(stats+(idx-1)*6).freq {
			tmp := st
			j := idx
			for {
				prev := p.readState(stats + (j-1)*6)
				p.writeState(stats+j*6, prev)
				j--
				if j == 0 || tmp.freq <= p.readState(stats+(j-1)*6).freq {
					break
				}
			}
			p.writeState(stats+j*6, tmp)
		} else {
			p.writeState(stats+idx*6, st)
		}
		i--
		if i == 0 {
			break
		}
	}
	last := p.readState(stats + idx*6)
	if last.freq == 0 {
		for {
			i++
			idx--
			if p.readState(stats+idx*6).freq != 0 {
				break
			}
		}
		escFreq += i
		ns := oldNS - i
		p.setNumStats(ctx, ns)
		if ns == 1 {
			tmp := p.readState(stats)
			for escFreq > 1 {
				tmp.freq -= tmp.freq >> 1
				escFreq >>= 1
			}
			p.sub.freeUnits(stats, (oldNS+1)>>1)
			p.writeState(oneState(ctx), tmp)
			p.found = oneState(ctx)
			return
		}
	}
	escFreq -= escFreq >> 1
	p.setSummFreq(ctx, p.summFreq(ctx)+escFreq)
	n0 := (oldNS + 1) >> 1
	n1 := (p.numStats(ctx) + 1) >> 1
	if n0 != n1 {
		p.setStats(ctx, p.sub.shrinkUnits(stats, n0, n1))
	}
	p.found = p.statsOff(ctx)
}

// createSuccessors 建后继链，0 表失败/复位。
func (p *PPM) createSuccessors(skip bool, p1 int) int {
	var ps [maxOrderPPM]int
	pps := 0
	pc := p.minCtx
	upBranch := p.readState(p.found).succ
	findIn := func(pc int) (int, bool) {
		if p.numStats(pc) != 1 {
			st := p.statsOff(pc)
			fs := p.readState(p.found).sym
			idx := 0
			for {
				if st+idx*6+6 > len(p.sub.heap) {
					return 0, false
				}
				if p.readState(st+idx*6).sym == fs {
					return st + idx*6, true
				}
				idx++
				if idx > 512 {
					return 0, false
				}
			}
		}
		return oneState(pc), true
	}
	// LOOP_ENTRY 共享体：检查后继，true 表跳出。
	loopEntry := func(state int) (brk bool, fail bool) {
		if p.readState(state).succ != upBranch {
			pc = p.readState(state).succ
			return true, false
		}
		if pps >= len(ps) {
			return false, true
		}
		ps[pps] = state
		pps++
		return false, false
	}
	done := false
	if !skip {
		ps[0] = p.found
		pps = 1
		done = p.suffix(pc) == 0
	}
	first := true
	for !done {
		cur := p1
		if p1 == 0 || !first {
			pc = p.suffix(pc)
			if pc == 0 || pc > len(p.sub.heap) {
				return 0
			}
			var ok bool
			cur, ok = findIn(pc)
			if !ok {
				return 0
			}
		} else {
			pc = p.suffix(pc)
		}
		first = false
		brk, fail := loopEntry(cur)
		if fail {
			return 0
		}
		if brk {
			break
		}
		done = p.suffix(pc) == 0
	}
	if pps == 0 {
		return pc
	}
	var upState ppmState
	upState.sym = p.sub.heap[upBranch]
	upState.succ = upBranch + 1
	if p.numStats(pc) != 1 {
		if pc <= p.sub.pText {
			return 0
		}
		st := p.statsOff(pc)
		idx := 0
		for {
			if st+idx*6+6 > len(p.sub.heap) {
				return 0
			}
			if p.readState(st+idx*6).sym == upState.sym {
				break
			}
			idx++
			if idx > 512 {
				return 0
			}
		}
		freq := int(p.readState(st + idx*6).freq)
		cf := uint32(freq - 1)
		s0 := uint32(p.summFreq(pc)-p.numStats(pc)) - cf
		if 2*cf <= s0 {
			upState.freq = 1
			if 5*cf > s0 {
				upState.freq = 2
			}
		} else {
			upState.freq = byte((2*cf+3*s0-1)/(2*s0) + 1)
		}
	} else {
		upState.freq = p.sub.heap[oneState(pc)+1]
	}
	for pps != 0 {
		pps--
		pc = p.createChild(pc, ps[pps], upState)
		if pc == 0 {
			return 0
		}
	}
	return pc
}

// updateModel 更新模型，false 表需复位上层。
func (p *PPM) updateModel() bool {
	fs := p.readState(p.found)
	var pst int
	var pc, successor int
	var ns1, ns, cf, sf, s0 uint32
	if fs.freq < maxFreq/4 {
		if pc = p.suffix(p.minCtx); pc != 0 {
			if p.numStats(pc) != 1 {
				st := p.statsOff(pc)
				idx := 0
				for p.readState(st+idx*6).sym != fs.sym {
					idx++
					if idx > 300 {
						return false
					}
				}
				pst = st + idx*6
				if idx > 0 {
					prev := p.readState(pst - 6)
					cur := p.readState(pst)
					if cur.freq >= prev.freq {
						p.writeState(pst, prev)
						p.writeState(pst-6, cur)
						pst -= 6
					}
				}
				cur := p.readState(pst)
				if cur.freq < maxFreq-9 {
					cur.freq += 2
					p.writeState(pst, cur)
					p.addSummFreq(pc, 2)
				}
			} else {
				pst = oneState(pc)
				cur := p.readState(pst)
				if cur.freq < 32 {
					cur.freq++
					p.writeState(pst, cur)
				}
			}
		}
	}
	if p.orderFall == 0 {
		succ := p.createSuccessors(true, pst)
		fcur := p.readState(p.found)
		fcur.succ = succ
		p.writeState(p.found, fcur)
		p.minCtx, p.maxCtx = succ, succ
		if succ == 0 {
			return false
		}
		return true
	}
	p.sub.heap[p.sub.pText] = fs.sym
	p.sub.pText++
	successor = p.sub.pText
	if p.sub.pText >= p.sub.fakeUnitsStart {
		return false
	}
	if fs.succ != 0 {
		if fs.succ <= p.sub.pText {
			fs.succ = p.createSuccessors(false, pst)
			if fs.succ == 0 {
				return false
			}
		}
		p.orderFall--
		if p.orderFall == 0 {
			successor = fs.succ
			if p.maxCtx != p.minCtx {
				p.sub.pText--
			}
		}
	} else {
		fcur := p.readState(p.found)
		fcur.succ = successor
		p.writeState(p.found, fcur)
		fs.succ = p.minCtx
	}
	s0 = uint32(p.summFreq(p.minCtx) - p.numStats(p.minCtx) - (int(fs.freq) - 1))
	ns = uint32(p.numStats(p.minCtx))
	for pc = p.maxCtx; pc != p.minCtx; pc = p.suffix(pc) {
		if pc == 0 {
			return false
		}
		if ns1 = uint32(p.numStats(pc)); ns1 != 1 {
			if ns1&1 == 0 {
				expanded := p.sub.expandUnits(p.statsOff(pc), int(ns1)>>1)
				if expanded == 0 {
					return false
				}
				p.setStats(pc, expanded)
			}
			inc := 0
			if 2*ns1 < ns {
				inc++
			}
			if 4*ns1 <= ns && uint32(p.summFreq(pc)) <= 8*ns1 {
				inc += 2
			}
			p.addSummFreq(pc, inc)
		} else {
			np := p.sub.allocUnits(1)
			if np == 0 {
				return false
			}
			p.writeState(np, p.readState(oneState(pc)))
			p.setStats(pc, np)
			cur := p.readState(np)
			if cur.freq < maxFreq/4-1 {
				cur.freq += cur.freq
			} else {
				cur.freq = maxFreq - 4
			}
			p.writeState(np, cur)
			extra := 0
			if ns > 3 {
				extra = 1
			}
			p.setSummFreq(pc, int(cur.freq)+p.initEsc+extra)
		}
		base := 2 * uint32(fs.freq) * (uint32(p.summFreq(pc)) + 6)
		sf = s0 + uint32(p.summFreq(pc))
		if base < 6*sf {
			cf = 1
			if base > sf {
				cf++
			}
			if base >= 4*sf {
				cf++
			}
			p.addSummFreq(pc, 3)
		} else {
			cf = 4
			if base >= 9*sf {
				cf++
			}
			if base >= 12*sf {
				cf++
			}
			if base >= 15*sf {
				cf++
			}
			p.addSummFreq(pc, int(cf))
		}
		nst := int(ns1)
		app := p.statsOff(pc) + nst*6
		p.writeState(app, ppmState{sym: fs.sym, freq: byte(cf), succ: successor})
		p.setNumStats(pc, nst+1)
	}
	p.maxCtx = fs.succ
	p.minCtx = fs.succ
	// 注意：与参考实现一致，局部 fs.succ 不写回 *FoundState。
	return true
}

// update1 更新单符号命中。
func (p *PPM) update1(ctx, pIdx int) {
	st := p.readState(pIdx)
	st.freq += 4
	p.writeState(pIdx, st)
	p.found = pIdx
	p.addSummFreq(ctx, 4)
	if pIdx == 0 {
		return // 损坏保护。
	}
	prev := p.readState(pIdx - 6)
	if st.freq > prev.freq {
		p.writeState(pIdx, prev)
		p.writeState(pIdx-6, st)
		p.found = pIdx - 6
		if st.freq > maxFreq {
			p.rescale(ctx)
		}
	}
}

// update2 更新 escape 命中。
func (p *PPM) update2(ctx, pIdx int) {
	st := p.readState(pIdx)
	st.freq += 4
	p.writeState(pIdx, st)
	p.found = pIdx
	p.addSummFreq(ctx, 4)
	if st.freq > maxFreq {
		p.rescale(ctx)
	}
	p.escCount++
	p.runLength = p.initRL
}

// decodeBinSymbol 解单状态上下文，false 表损坏。
func (p *PPM) decodeBinSymbol(ctx int) bool {
	rsOff := oneState(ctx)
	rs := p.readState(rsOff)
	if p.suffix(ctx) == 0 {
		return false
	}
	p.hiBitsFlag = p.hb2flag[p.readState(p.found).sym]
	bsIdx := int(p.prevSuccess) + int(p.ns2bsindx[p.numStats(p.suffix(ctx))-1]) +
		int(p.hiBitsFlag) + 2*int(p.hb2flag[rs.sym]) + int((p.runLength>>26)&0x20)
	if rs.freq == 0 || bsIdx < 0 || bsIdx >= 64 {
		return false
	}
	bs := &p.binSumm[rs.freq-1][bsIdx]
	if p.rcShiftCount(totBits) < int(*bs) {
		p.found = rsOff
		if rs.freq < 128 {
			rs.freq++
		}
		p.writeState(rsOff, rs)
		p.subLow, p.subHigh = 0, uint32(*bs)
		*bs = uint16(int16(int(*bs) + interval - getMean(*bs, periodBits, 2)))
		p.prevSuccess = 1
		p.runLength++
	} else {
		p.subLow = uint32(*bs)
		*bs = uint16(int16(int(*bs) - getMean(*bs, periodBits, 2)))
		p.subHigh = binScale
		p.initEsc = int(expEscape[*bs>>10])
		p.numMasked = 1
		p.charMask[rs.sym] = p.escCount
		p.prevSuccess = 0
		p.found = 0
	}
	return true
}

// decodeSymbol1 解多状态上下文首轮，false 表损坏/结束。
func (p *PPM) decodeSymbol1(ctx int) bool {
	ns := p.numStats(ctx)
	if ns < 1 || ns > 512 {
		return false
	}
	stats := p.statsOff(ctx)
	p.subScale = uint32(p.summFreq(ctx))
	count := p.rcCount()
	if count >= int(p.subScale) {
		return false
	}
	first := p.readState(stats)
	if count < int(first.freq) {
		p.subHigh = uint32(first.freq)
		if 2*int(p.subHigh) > int(p.subScale) {
			p.prevSuccess = 1
		} else {
			p.prevSuccess = 0
		}
		p.runLength += int(p.prevSuccess)
		first.freq += 4
		p.writeState(stats, first)
		p.found = stats
		p.addSummFreq(ctx, 4)
		if first.freq > maxFreq {
			p.rescale(ctx)
		}
		p.subLow = 0
		return true
	} else if p.found == 0 {
		return false
	}
	p.prevSuccess = 0
	i := ns - 1
	hi := int(first.freq)
	idx := 0
	for {
		idx++
		st := p.readState(stats + idx*6)
		hi += int(st.freq)
		if hi > count {
			break
		}
		i--
		if i == 0 {
			p.hiBitsFlag = p.hb2flag[p.readState(p.found).sym]
			p.subLow = uint32(hi)
			p.charMask[st.sym] = p.escCount
			p.numMasked = ns
			p.found = 0
			for j := idx - 1; j >= 0; j-- {
				p.charMask[p.readState(stats+j*6).sym] = p.escCount
			}
			p.subHigh = p.subScale
			return true
		}
	}
	p.subLow = uint32(hi) - uint32(p.readState(stats+idx*6).freq)
	p.subHigh = uint32(hi)
	p.update1(ctx, stats+idx*6)
	return true
}

// makeEscFreq2 取 escape 频率 SEE 上下文，nil 表损坏。
func (p *PPM) makeEscFreq2(ctx, diff int) *see2ctx {
	if p.numStats(ctx) != 256 {
		if p.suffix(ctx) == 0 || diff < 1 {
			return nil
		}
		// 注意：行列分开寻址（SEE2Cont[row]+off），不可折成线性下标。
		row := int(p.ns2indx[diff-1])
		off := 0
		if diff < p.numStats(p.suffix(ctx))-p.numStats(ctx) {
			off++
		}
		if uint32(p.summFreq(ctx)) < 11*uint32(p.numStats(ctx)) {
			off += 2
		}
		if p.numMasked > diff {
			off += 4
		}
		off += int(p.hiBitsFlag)
		s := &p.see2[row][off]
		p.subScale = uint32(s.getMean())
		return s
	}
	p.subScale = 1
	return &p.dummy
}

// decodeSymbol2 解后续轮，false 表损坏。
func (p *PPM) decodeSymbol2(ctx int) bool {
	ns := p.numStats(ctx)
	if ns < 1 || ns > 512 {
		return false
	}
	stats := p.statsOff(ctx)
	i := ns - p.numMasked
	if i < 1 {
		return false
	}
	psee := p.makeEscFreq2(ctx, i)
	if psee == nil {
		return false
	}
	var ps [256]int
	pps := 0
	hi := 0
	idx := -1
	rest := i
	for rest > 0 {
		for {
			idx++
			if idx >= ns {
				return false
			}
			if p.charMask[p.readState(stats+idx*6).sym] != p.escCount {
				break
			}
		}
		hi += int(p.readState(stats + idx*6).freq)
		if pps >= len(ps) {
			return false
		}
		ps[pps] = idx
		pps++
		rest--
	}
	p.subScale += uint32(hi)
	count := p.rcCount()
	if count >= int(p.subScale) {
		return false
	}
	if count < hi {
		hi = 0
		k := 0
		for {
			st := p.readState(stats + ps[k]*6)
			hi += int(st.freq)
			if hi > count {
				break
			}
			k++
			if k >= pps {
				return false
			}
		}
		p.subLow = uint32(hi) - uint32(p.readState(stats+ps[k]*6).freq)
		p.subHigh = uint32(hi)
		psee.update()
		p.update2(ctx, stats+ps[k]*6)
	} else {
		p.subLow = uint32(hi)
		p.subHigh = p.subScale
		for k := 0; k < pps; k++ {
			p.charMask[p.readState(stats+ps[k]*6).sym] = p.escCount
		}
		psee.summ += uint16(p.subScale)
		p.numMasked = ns
	}
	return true
}

// ClearMask 清掩码。
func (p *PPM) ClearMask() {
	p.escCount = 1
	for i := range p.charMask {
		p.charMask[i] = 0
	}
}

// DecodeChar 解一个字符（-1 表损坏）。
func (p *PPM) DecodeChar() int {
	if p.minCtx == 0 || p.minCtx <= p.sub.pText || p.minCtx > p.sub.heapEnd {
		return -1
	}
	if p.numStats(p.minCtx) != 1 {
		st := p.statsOff(p.minCtx)
		if st <= p.sub.pText || st > p.sub.heapEnd {
			return -1
		}
		if !p.decodeSymbol1(p.minCtx) {
			return -1
		}
	} else if !p.decodeBinSymbol(p.minCtx) {
		return -1
	}
	p.rcDecode()
	for p.found == 0 {
		p.rcNormalize()
		for {
			p.orderFall++
			p.minCtx = p.suffix(p.minCtx)
			if p.minCtx <= p.sub.pText || p.minCtx > p.sub.heapEnd {
				return -1
			}
			if p.numStats(p.minCtx) != p.numMasked {
				break
			}
		}
		if !p.decodeSymbol2(p.minCtx) {
			return -1
		}
		p.rcDecode()
	}
	sym := int(p.readState(p.found).sym)
	if p.orderFall == 0 {
		if succ := p.readState(p.found).succ; succ > p.sub.pText {
			p.minCtx, p.maxCtx = succ, succ
		} else {
			if !p.updateModel() {
				p.restartModelRare()
			}
			if p.escCount == 0 {
				p.ClearMask()
			}
		}
	} else {
		if !p.updateModel() {
			p.restartModelRare()
		}
		if p.escCount == 0 {
			p.ClearMask()
		}
	}
	p.rcNormalize()
	return sym
}
