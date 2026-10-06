package vint

import "testing"

func TestRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 127, 128, 300, 1 << 32, 1<<63 - 1, ^uint64(0)} {
		b := Encode(nil, v)
		got, n, err := Decode(b)
		if err != nil || got != v || n != len(b) {
			t.Fatalf("v=%d got=%d n=%d err=%v", v, got, n, err)
		}
	}
}

func TestTruncated(t *testing.T) {
	if _, _, err := Decode([]byte{0x80}); err == nil {
		t.Fatal("want error for truncated vint")
	}
}
