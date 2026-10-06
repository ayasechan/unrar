// Package vint 编解 RAR5 的小端 7bit 续位可变长整数。
package vint

import (
	"errors"
	"io"
)

// ErrOverflow 表示 vint 超出 uint64 范围。
var ErrOverflow = errors.New("vint: overflow")

// Decode 从 b 起解一个 vint，返回数值与消费字节数。
func Decode(b []byte) (uint64, int, error) {
	var v uint64
	for i, c := range b {
		if i == 10 {
			return 0, 0, ErrOverflow
		}
		v |= uint64(c&0x7f) << (7 * uint(i))
		if c&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, io.ErrUnexpectedEOF
}

// Encode 把 v 追加到 dst 后。
func Encode(dst []byte, v uint64) []byte {
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			dst = append(dst, c|0x80)
			continue
		}
		return append(dst, c)
	}
}
