package blake2s

import (
	"encoding/hex"
	"testing"
)

func TestVectors(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"},
		{"abc", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"},
	} {
		got := Sum256([]byte(tc.in))
		if hex.EncodeToString(got[:]) != tc.want {
			t.Fatalf("blake2s(%q) = %x", tc.in, got)
		}
	}
}

func TestLongerThanBlock(t *testing.T) {
	// 65 字节跨两块；与分段无关的确定性检查（不同长度必不同）。
	a := Sum256(make([]byte, 64))
	b := Sum256(make([]byte, 65))
	if a == b {
		t.Fatal("lengths must differ")
	}
	if Sum256(nil) != Sum256([]byte{}) {
		t.Fatal("empty forms must match")
	}
}
