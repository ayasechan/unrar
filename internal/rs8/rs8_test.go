package rs8

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, tc := range []struct{ data, par, miss int }{
		{10, 2, 1},
		{100, 4, 3},
		{200, 5, 5},
	} {
		data := make([]byte, tc.data)
		rng.Read(data)
		var c Coder
		c.Init(tc.par)
		par := make([]byte, tc.par)
		c.Encode(data, par)
		full := append(append([]byte(nil), data...), par...)
		// 擦除末尾 miss 个数据字节。
		eras := make([]int, 0, tc.miss)
		for i := 0; i < tc.miss; i++ {
			pos := tc.data - 1 - i
			full[pos] = 0
			eras = append(eras, pos)
		}
		var d Coder
		d.Init(tc.par)
		if !d.Decode(full, len(full), eras) {
			t.Fatalf("decode failed %+v", tc)
		}
		if !bytes.Equal(full[:tc.data], data) {
			t.Fatalf("mismatch %+v", tc)
		}
	}
}
