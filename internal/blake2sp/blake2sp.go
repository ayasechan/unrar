// Package blake2sp 实现 BLAKE2sp-256，用于 RAR5 文件哈希校验。
//
// BLAKE2sp 是 8 路并行的 BLAKE2s：输入按 64 字节轮询分发到 8 个叶哈希
// （参数 fanout=8、depth=2、node_offset=叶序号、node_depth=0），
// 8 个叶摘要再送入根哈希（node_depth=1）得最终 32 字节摘要。
// 构造对标 BLAKE2 官方参考实现 streaming 语义；压缩核心（G 函数、
// 10 轮、sigma、计数器、终结）与 RFC 7693 一致，已用官方 KAT 向量验证。
package blake2sp

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

// parallelism 是 BLAKE2sp 并行度（8 叶）。
const parallelism = 8

// Size 是摘要字节数。
const Size = 32

// errKeySize 表示密钥长度非法。
type keySizeError struct{}

func (keySizeError) Error() string { return "blake2sp: invalid key size" }

var errKeySize = keySizeError{}

func rotr(x uint32, n uint) uint32 { return x>>n | x<<(32-n) }

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

// compress 压一个 64 字节块；total 为已吸收字节数（含本块），
// last 置终结标志 f[0]，lastNode 置 f[1]（仅终结块有效）。
func compress(h *[8]uint32, block []byte, total uint64, last, lastNode bool) {
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
	if last && lastNode {
		v[15] = ^iv[7]
	} else {
		v[15] = iv[7]
	}
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

// digest 是单个 BLAKE2s 节点（叶或根），参数块全开。
type digest struct {
	h          [8]uint32
	buf        [64]byte
	used       int
	total      uint64
	outLen     int
	fanout     byte
	depth      byte
	leafLen    uint32
	nodeOffset uint32
	nodeDepth  byte
	innerLen   byte
	lastNode   bool
}

// init 按树参数初始化节点；key 只决定参数中的 key_length，absorbKey 为真
// 时才把 64 字节补零密钥块作为首块吸收（叶节点行为；根节点只取参数）。
// key 仅 KAT 验证用（RAR5 不用带密钥哈希）。
func (d *digest) init(outLen int, key []byte, absorbKey bool, fanout, depth byte, leafLen, nodeOffset uint32, nodeDepth, innerLen byte, lastNode bool) {
	d.h = iv
	d.h[0] ^= uint32(outLen) | uint32(len(key))<<8 | uint32(fanout)<<16 | uint32(depth)<<24
	d.h[1] ^= leafLen
	d.h[2] ^= nodeOffset
	d.h[3] ^= uint32(nodeDepth)<<16 | uint32(innerLen)<<24
	d.outLen = outLen
	d.fanout = fanout
	d.depth = depth
	d.leafLen = leafLen
	d.nodeOffset = nodeOffset
	d.nodeDepth = nodeDepth
	d.innerLen = innerLen
	d.lastNode = lastNode
	d.used = 0
	d.total = 0
	if absorbKey && len(key) > 0 {
		var kb [64]byte
		copy(kb[:], key)
		d.update(kb[:])
	}
}

// update 吸收数据（中间块无标志）。
func (d *digest) update(p []byte) {
	for len(p) > 0 {
		if d.used == 64 {
			d.total += 64
			compress(&d.h, d.buf[:], d.total, false, false)
			d.used = 0
		}
		n := copy(d.buf[d.used:], p)
		d.used += n
		p = p[n:]
	}
}

// sum 终结并返回摘要；不改动原状态，可重复调用。
func (d *digest) sum() [32]byte {
	h := d.h
	var last [64]byte
	copy(last[:], d.buf[:d.used])
	total := d.total + uint64(d.used)
	compress(&h, last[:], total, true, d.lastNode)
	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], h[i])
	}
	return out
}

// Hash 是流式 BLAKE2sp-256，实现 io.Writer；Sum 可重复调用。
type Hash struct {
	leaves   [parallelism]digest
	root     digest
	buf      [parallelism * 64]byte
	buffered int
	key      []byte // 仅 KAT 验证用；RAR5 路径恒为空。
}

// New 新建无密钥流式哈希（RAR5 用）。
func New() *Hash {
	h := &Hash{}
	h.Reset()
	return h
}

// NewKeyed 新建带密钥流式哈希，仅 KAT 验证用。
func NewKeyed(key []byte) (*Hash, error) {
	if len(key) == 0 || len(key) > 32 {
		return nil, errKeySize
	}
	h := &Hash{key: append([]byte(nil), key...)}
	h.Reset()
	return h, nil
}

// Reset 重建全部叶与根状态。
func (h *Hash) Reset() {
	for i := range h.leaves {
		h.leaves[i].init(Size, h.key, true, parallelism, 2, 0, uint32(i), 0, Size, i == parallelism-1)
	}
	h.root.init(Size, h.key, false, parallelism, 2, 0, 0, 1, Size, true)
	h.buffered = 0
}

// Write 写入数据，按 64 字节轮询分发到 8 叶。
func (h *Hash) Write(p []byte) (int, error) {
	n := len(p)
	if h.buffered > 0 && h.buffered+len(p) >= len(h.buf) {
		fill := len(h.buf) - h.buffered
		copy(h.buf[h.buffered:], p[:fill])
		for i := 0; i < parallelism; i++ {
			h.leaves[i].update(h.buf[i*64 : (i+1)*64])
		}
		p = p[fill:]
		h.buffered = 0
	}
	for len(p) >= len(h.buf) {
		for i := 0; i < parallelism; i++ {
			h.leaves[i].update(p[i*64 : (i+1)*64])
		}
		p = p[len(h.buf):]
	}
	h.buffered += copy(h.buf[h.buffered:], p)
	return n, nil
}

// Sum 终结并返回摘要；不改动原状态，可重复调用、可继续写入。
func (h *Hash) Sum() [32]byte {
	c := *h
	var digests [parallelism][32]byte
	for i := 0; i < parallelism; i++ {
		if c.buffered > i*64 {
			left := c.buffered - i*64
			if left > 64 {
				left = 64
			}
			c.leaves[i].update(c.buf[i*64 : i*64+left])
		}
		digests[i] = c.leaves[i].sum()
	}
	for i := 0; i < parallelism; i++ {
		c.root.update(digests[i][:])
	}
	return c.root.sum()
}

// Sum 计算 data 的 BLAKE2sp-256（无密钥）。
func Sum(data []byte) [32]byte {
	h := New()
	h.Write(data)
	return h.Sum()
}
