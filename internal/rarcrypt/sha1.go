package rarcrypt

import "encoding/binary"

// SHA-1 实现：标准变换 + RAR2.9 自修改输入变体（crypt3 KDF 用）。
// 标准部分与 crypto/sha1 逐字节对测（见测试）。

type sha1ctx struct {
	state [5]uint32
	count uint64
	buf   [64]byte
}

func rotl32(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }

func bitswap(x uint32) uint32 {
	return (x << 24) | ((x << 8) & 0xff0000) | ((x >> 8) & 0xff00) | (x >> 24)
}

func sha1Init(c *sha1ctx) {
	c.count = 0
	c.state[0] = 0x67452301
	c.state[1] = 0xEFCDAB89
	c.state[2] = 0x98BADCFE
	c.state[3] = 0x10325476
	c.state[4] = 0xC3D2E1F0
}

// transformBlock 变换 64 字节。w 为 16 字工作区（返回时含最后 16 个扩展字，
// 供 rar29 写回用）；inplace=true 时在 block 上原地做端序交换。
func transformBlock(state *[5]uint32, w *[16]uint32, block []byte, inplace bool) {
	if inplace {
		for i := 0; i < 16; i++ {
			v := binary.LittleEndian.Uint32(block[i*4:])
			w[i] = bitswap(v)
			binary.LittleEndian.PutUint32(block[i*4:], w[i])
		}
	} else {
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(block[i*4:])
		}
	}
	a, b, c, d, e := state[0], state[1], state[2], state[3], state[4]
	blk := func(i int) uint32 {
		v := w[(i+13)&15] ^ w[(i+8)&15] ^ w[(i+2)&15] ^ w[i&15]
		v = rotl32(v, 1)
		w[i&15] = v
		return v
	}
	for i := 0; i < 16; i++ {
		e += ((b & (c ^ d)) ^ d) + w[i] + 0x5A827999 + rotl32(a, 5)
		b = rotl32(b, 30)
		a, b, c, d, e = e, a, b, c, d
	}
	for i := 16; i < 20; i++ {
		e += ((b & (c ^ d)) ^ d) + blk(i) + 0x5A827999 + rotl32(a, 5)
		b = rotl32(b, 30)
		a, b, c, d, e = e, a, b, c, d
	}
	for i := 20; i < 40; i++ {
		e += (b ^ c ^ d) + blk(i) + 0x6ED9EBA1 + rotl32(a, 5)
		b = rotl32(b, 30)
		a, b, c, d, e = e, a, b, c, d
	}
	for i := 40; i < 60; i++ {
		e += (((b | c) & d) | (b & c)) + blk(i) + 0x8F1BBCDC + rotl32(a, 5)
		b = rotl32(b, 30)
		a, b, c, d, e = e, a, b, c, d
	}
	for i := 60; i < 80; i++ {
		e += (b ^ c ^ d) + blk(i) + 0xCA62C1D6 + rotl32(a, 5)
		b = rotl32(b, 30)
		a, b, c, d, e = e, a, b, c, d
	}
	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
	state[4] += e
}

// sha1Process 标准输入。
func sha1Process(c *sha1ctx, data []byte) {
	var w [16]uint32
	j := int(c.count & 63)
	c.count += uint64(len(data))
	i := 0
	if j+len(data) > 63 {
		i = 64 - j
		copy(c.buf[j:], data[:i])
		transformBlock(&c.state, &w, c.buf[:], true)
		for ; i+63 < len(data); i += 64 {
			transformBlock(&c.state, &w, data[i:i+64], false)
		}
		j = 0
	}
	if len(data) > i {
		copy(c.buf[j:], data[i:])
	}
}

// sha1ProcessRar29 自修改输入变体：每变换完一整块，把扩展字写回输入。
func sha1ProcessRar29(c *sha1ctx, data []byte) {
	var w [16]uint32
	j := int(c.count & 63)
	c.count += uint64(len(data))
	i := 0
	if j+len(data) > 63 {
		i = 64 - j
		copy(c.buf[j:], data[:i])
		transformBlock(&c.state, &w, c.buf[:], true)
		for ; i+63 < len(data); i += 64 {
			transformBlock(&c.state, &w, data[i:i+64], false)
			for k := 0; k < 16; k++ {
				binary.LittleEndian.PutUint32(data[i+k*4:], w[k])
			}
		}
		j = 0
	}
	if len(data) > i {
		copy(c.buf[j:], data[i:])
	}
}

// sha1Done 标准填充收尾，返回 5 字摘要。
func sha1Done(c *sha1ctx) [5]uint32 {
	var w [16]uint32
	bitLen := c.count * 8
	pos := int(c.count & 0x3f)
	c.buf[pos] = 0x80
	pos++
	if pos != 56 {
		if pos > 56 {
			for pos < 64 {
				c.buf[pos] = 0
				pos++
			}
			pos = 0
		}
		if pos == 0 {
			transformBlock(&c.state, &w, c.buf[:], true)
		}
		for pos < 56 {
			c.buf[pos] = 0
			pos++
		}
	}
	binary.BigEndian.PutUint32(c.buf[56:], uint32(bitLen>>32))
	binary.BigEndian.PutUint32(c.buf[60:], uint32(bitLen))
	transformBlock(&c.state, &w, c.buf[:], true)
	return c.state
}
