package blake2sp

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
)

// katKey 是官方 blake2sp-kat.txt 的固定密钥（00..1f）。
var katKey = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// kat 输入为 00..n-1 字节，含空串与 64/512 条带边界。
var katCases = []struct {
	length int
	want   string
}{
	{0, "715cb13895aeb678f6124160bff21465b30f4f6874193fc851b4621043f09cc6"},
	{1, "40578ffa52bf51ae1866f4284d3a157fc1bcd36ac13cbdcb0377e4d0cd0b6603"},
	{2, "67e3097545bad7e852d74d4eb548eca7c219c202a7d088db0efeac0eac304249"},
	{3, "8dbcc0589a3d17296a7a58e2f1eff0e2aa4210b58d1f88b86d7ba5f29dd3b583"},
	{63, "e85594700e3922a1e8e41eb8b064e7ac6d949d13b5a34523e5a6beac03c8ab29"},
	{64, "1d3701a5661bd31ab20562bd07b74dd19ac8f3524b73ce7bc996b788afd2f317"},
	{65, "874e1938033d7d383597a2a65f58b554e41106f6d1d50e9ba0eb685f6b6da071"},
	{127, "44cb6311d0750b7e33f7333aa78aaca9c34ad5f79c1b1591ec33951e69c4c461"},
	{128, "0c6ce32a3ea05612c5f8090f6a7e87f5ab30e41b707dcbe54155620ad770a340"},
	{129, "c65938dd3a053c729cf5b7c89f390bfebb5112766bb00aa5fa3164dfdf3b5647"},
	{191, "8c21e6568bc6dc00e3d6ebc09ea9c2ce006cd311d3b3e9cc9d8ddbfb3c5a7776"},
	{192, "525666968b3b7d007bb926b6efdc7e212a31154c9ae18d43ee0eb7e6b1a938d3"},
	{193, "e09a4fa5c28bdcd7c839840e0a383e4f7a102d0b1bc849c949627c4100c17dd3"},
	{254, "2b9158c722898e526d2cdd3fc088e9ffa79a9b73b7d2d24bc478e21cdb3b6763"},
	{255, "0c8a36597d7461c63a94732821c941856c668376606c86a52de0ee4104c615db"},
}

func katInput(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func TestKATKeyed(t *testing.T) {
	for _, tc := range katCases {
		h, err := NewKeyed(katKey)
		if err != nil {
			t.Fatal(err)
		}
		h.Write(katInput(tc.length))
		sum := h.Sum()
		got := hex.EncodeToString(sum[:])
		if got != tc.want {
			t.Fatalf("len %d = %s, want %s", tc.length, got, tc.want)
		}
	}
}

func TestStreamingEquivalence(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for _, n := range []int{0, 1, 63, 64, 65, 511, 512, 513, 1024, 5000} {
		data := make([]byte, n)
		rng.Read(data)
		h1, _ := NewKeyed(katKey)
		h1.Write(data)
		want := h1.Sum()
		// 随机切片写入必须一致。
		h2, _ := NewKeyed(katKey)
		rest := data
		for len(rest) > 0 {
			k := 1 + rng.Intn(300)
			if k > len(rest) {
				k = len(rest)
			}
			h2.Write(rest[:k])
			rest = rest[k:]
		}
		if got := h2.Sum(); got != want {
			t.Fatalf("len %d streaming mismatch", n)
		}
		// 无密钥路径同样必须自洽。
		u1 := New()
		u1.Write(data)
		u2 := New()
		for _, b := range data {
			u2.Write([]byte{b})
		}
		if u1.Sum() != u2.Sum() {
			t.Fatalf("len %d unkeyed streaming mismatch", n)
		}
	}
}

func TestSumIdempotentAndReset(t *testing.T) {
	h, _ := NewKeyed(katKey)
	h.Write([]byte("hello"))
	a, b := h.Sum(), h.Sum()
	if a != b {
		t.Fatal("Sum not idempotent")
	}
	// Sum 后可继续写入（状态未被破坏）。
	h.Write([]byte(" world"))
	h2, _ := NewKeyed(katKey)
	h2.Write([]byte("hello world"))
	if h.Sum() != h2.Sum() {
		t.Fatal("write after Sum diverged")
	}
	h.Reset()
	h3, _ := NewKeyed(katKey)
	if h.Sum() != h3.Sum() {
		t.Fatal("Reset mismatch")
	}
	// 空输入可终结。
	s0 := New().Sum()
	var zero [32]byte
	if bytes.Equal(s0[:], zero[:]) {
		t.Fatal("empty digest is zero")
	}
}

func TestBadKey(t *testing.T) {
	if _, err := NewKeyed(nil); err == nil {
		t.Fatal("nil key must fail")
	}
	if _, err := NewKeyed(make([]byte, 33)); err == nil {
		t.Fatal("33-byte key must fail")
	}
}
