package blake2s

import (
	"encoding/hex"
	"math/rand"
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

// TestXCryptoEquivalence 用旧纯 Go 实现输出的金值验证 x/crypto 汇编路径
// 摘要一致（含 55/56/57/63/64/65 字节块边界与 1MB 长输入）。
func TestXCryptoEquivalence(t *testing.T) {
	mk := func(n int, seed int64) []byte {
		b := make([]byte, n)
		rand.New(rand.NewSource(seed)).Read(b)
		return b
	}
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"empty", []byte{}, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"},
		{"abc", []byte("abc"), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"},
		{"55B", mk(55, 11), "51cb335193ada2841611b2bb4aa686ca950ba3fc8f8114f0f93e78f780e523ed"},
		{"56B", mk(56, 11), "950481bec6e3eba08334f3b599074b2dd73319a382be2758e1489ddfd4a93157"},
		{"57B", mk(57, 11), "9304dd1ed7da777525c742badc2945960067258adb4fea372a0385f4e0335102"},
		{"63B", mk(63, 12), "eeacf64764233739547542507929d65fba434afcacacdb068f6447ffa9675a4f"},
		{"64B", mk(64, 12), "1de730396f0408c9ff5f0d1047a181028ef4bf68211d1d90e0f4dc2dfed530a1"},
		{"65B", mk(65, 12), "5a4f4cec0064b60496351ac50181fde0be6693a4c1ad3f8c4739cc5fe5bb25ef"},
		{"128B", mk(128, 13), "4bc44a5787baf8cbf1d4be6cfd843d0d5f5b3abd1a7d6f8b13baa72856a06f66"},
		{"1MB", mk(1<<20, 14), "201ad9dc8051a0a429b0f7bdaad789b359e6252e8442295512fd8ff977c360d8"},
	} {
		got := Sum256(tc.data)
		if hex.EncodeToString(got[:]) != tc.want {
			t.Fatalf("%s: got %x want %s", tc.name, got, tc.want)
		}
		// 分片写入（1/7/64 字节交错）须与一次写入一致。
		h := New()
		for i := 0; i < len(tc.data); {
			n := 1 + (i*7)%64
			if n > len(tc.data)-i {
				n = len(tc.data) - i
			}
			h.Write(tc.data[i : i+n])
			i += n
		}
		if s := h.Sum(); s != got {
			t.Fatalf("%s: split write %x != oneshot %x", tc.name, s, got)
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
