// Package blake2s 实现 BLAKE2s-256（RFC 7693），用于 RAR5 文件校验。
// 标准库无此算法，自实现并以 RFC 向量验证。
package blake2s

import "encoding/binary"

var iv = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var sigma = [10][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

func rotr(x uint32, n uint) uint32 { return x>>n | x<<(32-n) }

// Sum256 计算 data 的 BLAKE2s-256（无 key、无 salt、无 personal）。
func Sum256(data []byte) [32]byte {
	h := New()
	h.Write(data)
	return h.Sum()
}

// Hash 是流式 BLAKE2s-256。
type Hash struct {
	h     [8]uint32
	buf   [64]byte
	used  int
	total uint64
}

// New 新建流式哈希。
func New() *Hash {
	h := &Hash{}
	h.h = iv
	h.h[0] ^= 0x01010000 ^ 0x00<<8 ^ 0x20
	return h
}

// Write 写入数据。
func (hh *Hash) Write(data []byte) (int, error) {
	wrote := 0
	for len(data) > 0 {
		if hh.used == 64 {
			hh.total += 64
			compress(&hh.h, hh.buf[:], hh.total, false)
			hh.used = 0
		}
		n := copy(hh.buf[hh.used:], data)
		hh.used += n
		wrote += n
		data = data[n:]
	}
	return wrote, nil
}

// Sum 收尾并返回摘要（可继续写入？否：收尾后状态终结）。
func (hh *Hash) Sum() [32]byte {
	var last [64]byte
	copy(last[:], hh.buf[:hh.used])
	total := hh.total + uint64(hh.used)
	compress(&hh.h, last[:], total, true)
	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], hh.h[i])
	}
	return out
}

func g(v *[16]uint32, a, b, c, d int, x, y uint32) {
	v[a] += v[b] + x
	v[d] = rotr(v[d]^v[a], 16)
	v[c] += v[d]
	v[b] = rotr(v[b]^v[c], 12)
	v[a] += v[b] + y
	v[d] = rotr(v[d]^v[a], 8)
	v[c] += v[d]
	v[b] = rotr(v[b]^v[c], 7)
}

func compress(h *[8]uint32, block []byte, total uint64, last bool) {
	var m [16]uint32
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(block[i*4:])
	}
	var v [16]uint32
	copy(v[:8], h[:])
	v[8] = iv[0]
	v[9] = iv[1]
	v[10] = iv[2]
	v[11] = iv[3]
	v[12] = iv[4] ^ uint32(total)
	v[13] = iv[5] ^ uint32(total>>32)
	if last {
		v[14] = ^iv[6]
	} else {
		v[14] = iv[6]
	}
	v[15] = iv[7]
	for r := 0; r < 10; r++ {
		s := sigma[r]
		g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}
