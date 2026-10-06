package rs16

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	const nd, nr = 5, 2
	const size = 4096
	datas := make([][]byte, nd)
	for i := range datas {
		datas[i] = make([]byte, size)
		rng.Read(datas[i])
	}
	// 编码。
	var enc Coder
	if !enc.Init(nd, nr, nil) {
		t.Fatal("enc init")
	}
	eccs := make([][]byte, nr)
	for i := range eccs {
		eccs[i] = make([]byte, size)
	}
	for d := uint(0); d < nd; d++ {
		for e := uint(0); e < nr; e++ {
			enc.UpdateECC(d, e, datas[d], eccs[e], size)
		}
	}
	// 擦除 2 卷数据（data1、data3），用 ecc 重建。
	valid := make([]bool, nd+nr)
	for i := range valid {
		valid[i] = true
	}
	valid[1], valid[3] = false, false
	var dec Coder
	if !dec.Init(nd, nr, valid) {
		t.Fatal("dec init")
	}
	// 按 Restore 流程：缺卷用 rev 数据替代，解码输出到 Buf。
	revPool := [][]byte{eccs[0], eccs[1]}
	used := 0
	unit := make([][]byte, nd)
	for i := range unit {
		if valid[i] {
			unit[i] = datas[i]
		} else {
			unit[i] = revPool[used]
			used++
		}
	}
	out := make([][]byte, 2)
	for i := range out {
		out[i] = make([]byte, size)
	}
	for d := uint(0); d < nd; d++ {
		for e := uint(0); e < 2; e++ {
			dec.UpdateECC(d, e, unit[d], out[e], size)
		}
	}
	if !bytes.Equal(out[0], datas[1]) || !bytes.Equal(out[1], datas[3]) {
		t.Fatal("recovery mismatch")
	}
}

func TestTooManyErasures(t *testing.T) {
	var dec Coder
	valid := []bool{true, false, false, true, true}
	if dec.Init(3, 1, valid) {
		t.Fatal("should reject NE > ValidECC")
	}
}
