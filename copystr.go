package rar

// lzWindow 是 LZ 解包共用的滑动窗口与匹配状态。
// v29 与 v50 的 CopyString/InsertOldDist 语义相同（模窗口），
// 循环顶的回绕与落盘条件各自保留（v29 掩码/v50 单减）。
type lzWindow struct {
	win          []byte
	winSize      uint64
	unpPtr       uint64
	wrPtr        uint64
	prevPtr      uint64
	firstWinDone bool
	oldDist      [4]uint64
	lastLength   uint64
	writeBorder  uint64
}

// resetFresh 非固实链首的窗口与匹配状态复位（同尺寸复用缓冲）。
func (w *lzWindow) resetFresh(winSize uint64) {
	if uint64(cap(w.win)) < winSize {
		w.win = make([]byte, winSize)
	} else {
		// 复用缓冲；FirstWinDone 复位后旧内容不可达，无需清零。
		w.win = w.win[:winSize]
	}
	w.winSize = winSize
	w.oldDist[0], w.oldDist[1], w.oldDist[2], w.oldDist[3] = ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)
	w.unpPtr, w.wrPtr, w.prevPtr = 0, 0, 0
	w.firstWinDone = false
	w.lastLength = 0
	if w.winSize < 0x400000 {
		w.writeBorder = w.winSize
	} else {
		w.writeBorder = 0x400000
	}
}

func (w *lzWindow) insertOldDist(d uint64) {
	w.oldDist[3] = w.oldDist[2]
	w.oldDist[2] = w.oldDist[1]
	w.oldDist[1] = w.oldDist[0]
	w.oldDist[0] = d
}

// smallOverlapScalar 是重叠拷贝走逐字节线性循环的长度上限。
// 短匹配（len 2..10 为主）调一次 copy 的开销反而大于十几次赋值，
// 超过该长度的重叠展开才值得用倍增 copy。
const smallOverlapScalar = 32

// copyString 从窗口拷贝匹配串；非法距离填零（损坏容错）。
// 快路径：按窗口回绕点切分为线性段，段内无回绕分支；
// 不交叠段一次 copy，重叠段倍增展开（先搬 distance 字节再翻倍，
// 源区已完全落定，copy 的 memmove 语义与逐字节结果一致）。
func (w *lzWindow) copyString(length, distance uint64) {
	if length == 0 || w.winSize == 0 {
		return
	}
	if w.unpPtr >= w.winSize {
		w.unpPtr %= w.winSize
	}
	// 非法距离填零：原语义为 distance > winSize，或首窗口未填满时的远距离引用。
	if distance > w.winSize || (distance > w.unpPtr && !w.firstWinDone) {
		for length > 0 {
			n := w.winSize - w.unpPtr
			if n > length {
				n = length
			}
			clear(w.win[w.unpPtr : w.unpPtr+n])
			w.unpPtr += n
			if w.unpPtr >= w.winSize {
				w.unpPtr = 0
			}
			length -= n
		}
		return
	}
	src := w.unpPtr - distance
	if distance > w.unpPtr {
		src += w.winSize
	}
	for length > 0 {
		// 线性段：src 与 unpPtr 都不回绕。
		chunk := length
		if n := w.winSize - w.unpPtr; chunk > n {
			chunk = n
		}
		if n := w.winSize - src; chunk > n {
			chunk = n
		}
		dst := w.unpPtr
		switch {
		case src >= dst || distance >= chunk:
			// src 在后（已回绕）读必先于写，或逻辑无交叠：一次 copy。
			copy(w.win[dst:dst+chunk], w.win[src:src+chunk])
		case chunk <= smallOverlapScalar:
			// 短重叠：线性逐字节，无回绕分支。
			for i := uint64(0); i < chunk; i++ {
				w.win[dst+i] = w.win[src+i]
			}
		default:
			// 长重叠：先搬 distance 字节（与目标相邻无交叠），再倍增；
			// 每次源区已完全写入，copy 与逐字节等价。
			copy(w.win[dst:dst+distance], w.win[src:src+distance])
			copied := distance
			for copied < chunk {
				n := copied
				if n > chunk-copied {
					n = chunk - copied
				}
				copy(w.win[dst+copied:dst+copied+n], w.win[dst:dst+n])
				copied += n
			}
		}
		w.unpPtr += chunk
		if w.unpPtr >= w.winSize {
			w.unpPtr = 0
		}
		src += chunk
		if src >= w.winSize {
			src = 0
		}
		length -= chunk
	}
}
