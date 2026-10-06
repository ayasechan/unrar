// Package blake2s 提供 BLAKE2s-256（RFC 7693），用于 RAR5 文件校验。
// 基于 golang.org/x/crypto/blake2s（amd64 含 SSE2/SSSE3/SSE4.1 汇编），
// 本包仅保留本仓所需的最小流式 API，根包调用点无需改动。
package blake2s

import (
	"hash"

	xblake2s "golang.org/x/crypto/blake2s"
)

// Sum256 计算 data 的 BLAKE2s-256（无 key）。
func Sum256(data []byte) [32]byte {
	h := New()
	h.Write(data)
	return h.Sum()
}

// Hash 是流式 BLAKE2s-256，实现 io.Writer。
type Hash struct {
	h hash.Hash
}

// New 新建流式哈希。
func New() *Hash {
	// nil key 永不报错，摘要即标准 BLAKE2s-256。
	h, _ := xblake2s.New256(nil)
	return &Hash{h: h}
}

// Write 写入数据。
func (hh *Hash) Write(data []byte) (int, error) {
	return hh.h.Write(data)
}

// Sum 收尾并返回摘要。
func (hh *Hash) Sum() [32]byte {
	var out [32]byte
	copy(out[:], hh.h.Sum(nil))
	return out
}
