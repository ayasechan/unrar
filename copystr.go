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

// copyString 从窗口拷贝匹配串；非法距离填零（损坏容错）。
func (w *lzWindow) copyString(length, distance uint64) {
	src := w.unpPtr - distance
	if distance > w.unpPtr {
		src += w.winSize
		if distance > w.winSize || !w.firstWinDone {
			for length > 0 {
				w.win[w.unpPtr] = 0
				w.unpPtr++
				if w.unpPtr >= w.winSize {
					w.unpPtr = 0
				}
				length--
			}
			return
		}
	}
	for length > 0 {
		w.win[w.unpPtr] = w.win[src]
		src++
		if src >= w.winSize {
			src = 0
		}
		w.unpPtr++
		if w.unpPtr >= w.winSize {
			w.unpPtr = 0
		}
		length--
	}
}
