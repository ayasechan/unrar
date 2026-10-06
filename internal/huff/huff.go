// Package huff 提供 RAR 解包用的 Huffman 解码表。
package huff

import "github.com/ayasechan/unrar/internal/bitio"

// MaxQuickBits 是快速解码上限。
const MaxQuickBits = 9

// Table 是 Huffman 解码表。
type Table struct {
	MaxNum    int
	DecodeLen [16]uint
	DecodePos [16]uint
	QuickBits uint
	QuickLen  [1 << MaxQuickBits]uint
	QuickNum  [1 << MaxQuickBits]uint16
	DecodeNum []uint16
}

// MakeTables 由码长表构造解码表。
func MakeTables(lengthTable []byte, size int) *Table {
	t := &Table{MaxNum: size, DecodeNum: make([]uint16, size)}
	var lengthCount [16]uint
	for i := 0; i < size; i++ {
		lengthCount[lengthTable[i]&0xf]++
	}
	lengthCount[0] = 0
	t.DecodePos[0] = 0
	t.DecodeLen[0] = 0
	upper := uint(0)
	for i := 1; i < 16; i++ {
		upper += lengthCount[i]
		t.DecodeLen[i] = upper << (16 - uint(i))
		upper *= 2
		t.DecodePos[i] = t.DecodePos[i-1] + lengthCount[i-1]
	}
	copyPos := t.DecodePos
	for i := 0; i < size; i++ {
		if l := lengthTable[i] & 0xf; l != 0 {
			t.DecodeNum[copyPos[l]] = uint16(i)
			copyPos[l]++
		}
	}
	switch size {
	case 306, 298, 299: // NC / NC20 / NC30
		t.QuickBits = MaxQuickBits
	default:
		t.QuickBits = MaxQuickBits - 3
	}
	quickSize := uint(1 << t.QuickBits)
	curLen := uint(1)
	for code := uint(0); code < quickSize; code++ {
		field := code << (16 - t.QuickBits)
		for curLen < uint(len(t.DecodeLen)) && field >= t.DecodeLen[curLen] {
			curLen++
		}
		t.QuickLen[code] = curLen
		dist := field - t.DecodeLen[curLen-1]
		dist >>= 16 - curLen
		// Now we can calculate the position in the code list.
		if curLen < uint(len(t.DecodePos)) {
			if pos := t.DecodePos[curLen] + dist; int(pos) < size {
				t.QuickNum[code] = t.DecodeNum[pos]
			}
		}
	}
	return t
}

// Decode 解一个码字。
func (t *Table) Decode(br *bitio.Reader) uint {
	field := uint(br.GetBits()) & 0xfffe
	if field < t.DecodeLen[t.QuickBits] {
		code := field >> (16 - t.QuickBits)
		br.AddBits(t.QuickLen[code])
		return uint(t.QuickNum[code])
	}
	bits := uint(15)
	for i := t.QuickBits + 1; i < 15; i++ {
		if field < t.DecodeLen[i] {
			bits = i
			break
		}
	}
	br.AddBits(bits)
	dist := field - t.DecodeLen[bits-1]
	dist >>= 16 - bits
	pos := t.DecodePos[bits] + dist
	if int(pos) >= t.MaxNum {
		pos = 0
	}
	return uint(t.DecodeNum[pos])
}
