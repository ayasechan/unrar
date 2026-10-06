package rar

import (
	"bytes"
	"math/rand"
	"testing"
)

// refCopyString 是重写前的逐字节实现，仅作差分参照。
func refCopyString(w *lzWindow, length, distance uint64) {
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

func cloneWindow(w *lzWindow) *lzWindow {
	c := *w
	c.win = append([]byte(nil), w.win...)
	return &c
}

func TestCopyStringDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	winSizes := []uint64{256, 4096, 1 << 20}
	dists := []uint64{0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100, 255, 256, 257, 4095, 4096, 4097}
	lens := []uint64{0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 100, 300, 1000, 4096, 5000, 70000}
	for _, ws := range winSizes {
		for i := 0; i < 300; i++ {
			base := &lzWindow{}
			base.resetFresh(ws)
			rng.Read(base.win)
			base.unpPtr = uint64(rng.Int63n(int64(ws)))
			base.firstWinDone = rng.Intn(2) == 0
			d := dists[rng.Intn(len(dists))]
			// 混入回绕边界与非法距离。
			switch rng.Intn(6) {
			case 0:
				d = base.unpPtr + uint64(rng.Intn(8))
			case 1:
				d = ws + uint64(rng.Intn(3)) - 1
			case 2:
				d = uint64(rng.Int63n(int64(ws) * 2))
			}
			l := lens[rng.Intn(len(lens))]
			if l > ws*2 {
				l = ws * 2
			}
			a, b := cloneWindow(base), cloneWindow(base)
			a.copyString(l, d)
			refCopyString(b, l, d)
			if a.unpPtr != b.unpPtr {
				t.Fatalf("ws=%d unpPtr=%d firstWin=%v len=%d dist=%d: unpPtr %d != ref %d",
					ws, base.unpPtr, base.firstWinDone, l, d, a.unpPtr, b.unpPtr)
			}
			if !bytes.Equal(a.win, b.win) {
				t.Fatalf("ws=%d unpPtr=%d firstWin=%v len=%d dist=%d: window mismatch",
					ws, base.unpPtr, base.firstWinDone, l, d)
			}
		}
	}
}

func TestCopyStringEdges(t *testing.T) {
	// dist=0 自拷贝空操作（指针照常推进）。
	w := &lzWindow{}
	w.resetFresh(256)
	for i := range w.win {
		w.win[i] = byte(i)
	}
	w.unpPtr = 100
	w.firstWinDone = true
	before := append([]byte(nil), w.win...)
	w.copyString(10, 0)
	if w.unpPtr != 110 {
		t.Fatalf("dist=0 unpPtr=%d want 110", w.unpPtr)
	}
	if !bytes.Equal(w.win, before) {
		t.Fatal("dist=0 must not modify window")
	}
	// 非法距离填零且跨回绕。
	w.unpPtr = 250
	w.firstWinDone = false
	w.copyString(10, 300)
	if w.unpPtr != 4 {
		t.Fatalf("zero fill unpPtr=%d want 4", w.unpPtr)
	}
	for i := 250; i < 256; i++ {
		if w.win[i] != 0 {
			t.Fatalf("win[%d]=%x want 0", i, w.win[i])
		}
	}
	for i := 0; i < 4; i++ {
		if w.win[i] != 0 {
			t.Fatalf("win[%d]=%x want 0", i, w.win[i])
		}
	}
}
