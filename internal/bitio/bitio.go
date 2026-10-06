// Package bitio 提供 RAR 解包用的 MSB 优先滑动位流。
//
// 语义对齐 32KB 滑动缓冲：消费过半即压缩，已消费字节被丢弃；
// 读尽底层流后尾部按零对待，调用方须在越界前用 Refill 续流。
package bitio

import "io"

// MaxSize 是滑动缓冲大小。
const MaxSize = 0x8000

// Reader 是位流读取器。
type Reader struct {
	Buf     []byte // 长 MaxSize+16，尾部补零区。
	InAddr  int
	InBit   uint
	ReadTop int
	src     io.Reader
	failed  bool
}

// NewReader 构造位流读取器。
func NewReader(src io.Reader) *Reader {
	// 尾垫 16 字节，保证 GetBits64 在 InAddr 顶格时仍可读。
	return &Reader{Buf: make([]byte, MaxSize+16), src: src}
}

// GetBits 预览当前位置 16 位（MSB 优先），不消费。
func (b *Reader) GetBits() uint16 {
	b0 := uint32(b.Buf[b.InAddr])
	b1 := uint32(b.Buf[b.InAddr+1])
	b2 := uint32(b.Buf[b.InAddr+2])
	field := (b0<<16 | b1<<8 | b2) >> (8 - b.InBit)
	return uint16(field & 0xffff)
}

// AddBits 消费 n 位。
func (b *Reader) AddBits(n uint) {
	n += b.InBit
	b.InAddr += int(n >> 3)
	b.InBit = n & 7
}

// NeedRefill 报告是否应续流（距已读尾不足 30 字节）。
func (b *Reader) NeedRefill() bool {
	return b.InAddr > b.ReadTop-30
}

// GetBits32 预览当前位置 32 位（MSB 优先），不消费。
func (b *Reader) GetBits32() uint32 {
	hi := uint32(b.Buf[b.InAddr])<<24 | uint32(b.Buf[b.InAddr+1])<<16 |
		uint32(b.Buf[b.InAddr+2])<<8 | uint32(b.Buf[b.InAddr+3])
	lo := uint32(b.Buf[b.InAddr+4])
	return hi<<b.InBit | lo>>(8-b.InBit)
}

// GetBits64 预览当前位置 64 位（MSB 优先），不消费。
func (b *Reader) GetBits64() uint64 {
	hi := uint64(b.Buf[b.InAddr])<<56 | uint64(b.Buf[b.InAddr+1])<<48 |
		uint64(b.Buf[b.InAddr+2])<<40 | uint64(b.Buf[b.InAddr+3])<<32 |
		uint64(b.Buf[b.InAddr+4])<<24 | uint64(b.Buf[b.InAddr+5])<<16 |
		uint64(b.Buf[b.InAddr+6])<<8 | uint64(b.Buf[b.InAddr+7])
	lo := uint64(b.Buf[b.InAddr+8])
	return hi<<b.InBit | lo>>(8-b.InBit)
}
func (b *Reader) NeedRefillSmall() bool {
	return b.InAddr > b.ReadTop-5
}

// GetByte 读一个字节（PPM/RangeCoder 用，对齐 GetChar）。
// 位流须已对齐到字节边界；失败返回 0。
func (b *Reader) GetByte() byte {
	if b.InAddr > MaxSize-30 {
		if !b.Refill() {
			return 0
		}
		if b.InAddr >= MaxSize {
			return 0
		}
	}
	c := b.Buf[b.InAddr]
	b.InAddr++
	return c
}

// Overrun 报告是否已越过已读尾（损坏保护）。
func (b *Reader) Overrun() bool {
	return b.InAddr > b.ReadTop
}

// Refill 续流，硬错误（非 EOF 的读错）返回 false。
func (b *Reader) Refill() bool {
	if b.failed {
		return false
	}
	left := b.ReadTop - b.InAddr
	if left < 0 {
		return false
	}
	if b.InAddr > MaxSize/2 {
		copy(b.Buf, b.Buf[b.InAddr:b.ReadTop])
		b.InAddr = 0
		b.ReadTop = left
	} else {
		left = b.ReadTop
	}
	n, err := b.src.Read(b.Buf[left:MaxSize])
	if n > 0 {
		b.ReadTop += n
	}
	if err != nil && err != io.EOF {
		b.failed = true
		return false
	}
	return true
}
