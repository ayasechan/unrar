package rar

import (
	"math/rand"
	"testing"
)

// BenchmarkCopyStringDist1 RLE 场景：dist=1 单字节重复展开。
func BenchmarkCopyStringDist1(b *testing.B) {
	const winSize = 1 << 20
	w := &lzWindow{}
	w.resetFresh(winSize)
	w.win[0] = 0xab
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.unpPtr = 1
		w.firstWinDone = true
		w.copyString(4096, 1)
	}
}

// BenchmarkCopyStringDist4 短重叠：dist=4 len=8。
func BenchmarkCopyStringDist4(b *testing.B) {
	const winSize = 1 << 20
	w := &lzWindow{}
	w.resetFresh(winSize)
	for i := uint64(0); i < 4; i++ {
		w.win[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.unpPtr = 4
		w.firstWinDone = true
		w.copyString(8, 4)
	}
}

// BenchmarkCopyStringLarge 非重叠大块：dist>=len。
func BenchmarkCopyStringLarge(b *testing.B) {
	const winSize = 1 << 20
	w := &lzWindow{}
	w.resetFresh(winSize)
	rng := rand.New(rand.NewSource(3))
	rng.Read(w.win[:winSize])
	b.SetBytes(4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.unpPtr = 8192
		w.firstWinDone = true
		w.copyString(4096, 4096)
	}
}

// BenchmarkCopyStringLen2 短匹配 len=2。
func BenchmarkCopyStringLen2(b *testing.B) {
	const winSize = 1 << 20
	w := &lzWindow{}
	w.resetFresh(winSize)
	for i := uint64(0); i < 256; i++ {
		w.win[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.unpPtr = 128
		w.firstWinDone = true
		w.copyString(2, 5)
	}
}

// BenchmarkCopyStringOverlapLarge 长重叠：dist=4 len=4096。
func BenchmarkCopyStringOverlapLarge(b *testing.B) {
	const winSize = 1 << 20
	w := &lzWindow{}
	w.resetFresh(winSize)
	for i := uint64(0); i < 4; i++ {
		w.win[i] = byte(i + 1)
	}
	b.SetBytes(4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.unpPtr = 4
		w.firstWinDone = true
		w.copyString(4096, 4)
	}
}

// BenchmarkCopyStringWrap 回绕：unpPtr 贴尾，src 与 dst 双双跨尾。
func BenchmarkCopyStringWrap(b *testing.B) {
	const winSize = 1 << 20
	w := &lzWindow{}
	w.resetFresh(winSize)
	rng := rand.New(rand.NewSource(4))
	rng.Read(w.win)
	b.SetBytes(4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.unpPtr = winSize - 100
		w.firstWinDone = true
		w.copyString(4096, 8192)
	}
}
