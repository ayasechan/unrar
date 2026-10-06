package rarcrypt

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

func digestBE(d [5]uint32) [20]byte {
	var out [20]byte
	for k, w := range d {
		out[k*4] = byte(w >> 24)
		out[k*4+1] = byte(w >> 16)
		out[k*4+2] = byte(w >> 8)
		out[k*4+3] = byte(w)
	}
	return out
}

func TestSHA1AgainstStdlib(t *testing.T) {
	inputs := [][]byte{
		{},
		[]byte("abc"),
		[]byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
	}
	for _, in := range inputs {
		var c sha1ctx
		sha1Init(&c)
		sha1Process(&c, in)
		if got, want := digestBE(sha1Done(&c)), sha1.Sum(in); got != want {
			t.Fatalf("sha1(%q) = %x want %x", in, got, want)
		}
	}
	buf := make([]byte, 5000)
	rand.Read(buf)
	var c sha1ctx
	sha1Init(&c)
	for off := 0; off < len(buf); {
		n := 63
		if off+n > len(buf) {
			n = len(buf) - off
		}
		sha1Process(&c, buf[off:off+n])
		off += n
	}
	if got, want := digestBE(sha1Done(&c)), sha1.Sum(buf); got != want {
		t.Fatalf("sha1(5000B) mismatch")
	}
}

// TestPBKDF2Vectors 用源码内自带的三组 Key 向量验证。
func TestPBKDF2Vectors(t *testing.T) {
	for _, tc := range []struct {
		pwd  string
		salt string
		lg2  byte
		want string
	}{
		{"password", "salt", 0, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 12, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
		{"just some long string pretending to be a password", "salt, salt, salt, a lot of salt", 16,
			"080fa31d422db047839bce3a3bce4951e262b9ff762f57e9c47196ce4b6b6ebf"},
	} {
		key, _, _, ok := KDF5(tc.pwd, []byte(tc.salt), tc.lg2)
		if !ok {
			t.Fatal("KDF5 rejected")
		}
		if got := hex.EncodeToString(key[:]); got != tc.want {
			t.Fatalf("pbkdf2(%q) = %s want %s", tc.pwd, got, tc.want)
		}
	}
}

func TestPasswordPrep(t *testing.T) {
	if got := WideToRaw("Ab"); string(got) != "A\x00b\x00" {
		t.Fatalf("raw = %x", got)
	}
	if got := string(WideToUTF8("é")); got != "é" {
		t.Fatalf("utf = %q", got)
	}
	long := string(make([]rune, 200))
	if len([]rune(TruncatePassword(long))) != 127 {
		t.Fatal("no truncation")
	}
}
