package rar

import (
	"strings"
	"testing"
)

func TestDecodeANSIName(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		enc  FilenameEncoding
		want string
	}{
		{"gbk", []byte{0xD6, 0xD0, 0xCE, 0xC4}, EncodingGBK, "中文"},
		{"big5", []byte{0xA4, 0xA4, 0xA4, 0xE5}, EncodingBig5, "中文"},
		{"shiftjis", []byte{0x82, 0xA0}, EncodingShiftJIS, "あ"},
		{"euckr", []byte{0xC7, 0xD1}, EncodingEUCKR, "한"},
		{"ascii-gbk", []byte("hello.txt"), EncodingGBK, "hello.txt"},
		{"default-passthrough", []byte{0xD6, 0xD0}, "", "\xd6\xd0"},
		{"utf8-passthrough", []byte{0xD6, 0xD0}, EncodingUTF8, "\xd6\xd0"},
		{"unknown-passthrough", []byte{0xD6, 0xD0}, "xxx", "\xd6\xd0"},
	} {
		if got := decodeANSIName(tc.raw, tc.enc); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestDecodeANSINameBroken(t *testing.T) {
	// 坏字节只替换不报错：GBK 下孤立 0x80 非法。
	got := decodeANSIName([]byte{0x61, 0x80, 0x62}, EncodingGBK)
	if !strings.Contains(got, "a") || !strings.Contains(got, "b") {
		t.Fatalf("broken bytes must preserve surroundings, got %q", got)
	}
	if got == "a\x80b" {
		t.Fatalf("broken byte must not pass through raw, got %q", got)
	}
}
