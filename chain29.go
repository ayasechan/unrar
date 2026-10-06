package rar

import (
	"hash/crc32"
	"io"

	"github.com/ayasechan/unrar/internal/bitio"
	"github.com/ayasechan/unrar/internal/blake2s"
)

// openChain29 解固实链（或单文件）并返回目标文件流。
// 链上前置文件解后丢弃（仍校验 CRC），目标文件流式输出。
func (f *File) openChain29() (io.ReadCloser, error) {
	r := f.r
	idx := -1
	for i, ff := range r.File {
		if ff == f {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, ErrChecksum
	}
	start := idx
	if r.solidArc {
		start = 0
	} else {
		for start > 0 && r.File[start].data.solid {
			start--
		}
	}
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(r.decodeChain29(start, idx, pw))
	}()
	return pr, nil
}

// decodeChain29 顺序解 start..idx，目标输出到 w。
func (r *Reader) decodeChain29(start, idx int, w io.Writer) error {
	u := &unpack29{}
	h := crc32.NewIEEE()
	var b2 *blake2s.Hash
	for i := start; i <= idx; i++ {
		cf := r.File[i]
		if cf.IsDir || cf.data.method == 0 {
			continue
		}
		if cf.data.unpVer != 29 {
			return ErrUnsupported
		}
		stream, sc, err := r.cryptStream(cf)
		if err != nil {
			return err
		}
		if err := u.init(cf.data.winSize, i > start); err != nil {
			return err
		}
		br := bitio.NewReader(stream)
		dest := int64(cf.data.unpSize)
		if cf.data.sizeUnknown {
			dest = -1
		}
		h.Reset()
		hasB2 := len(cf.data.blake2) > 0
		if hasB2 {
			if b2 == nil {
				b2 = blake2s.New()
			} else {
				b2.Reset()
			}
		}
		var out io.Writer = h
		isTarget := i == idx
		switch {
		case hasB2 && isTarget:
			out = io.MultiWriter(h, b2, w)
		case hasB2:
			out = io.MultiWriter(h, b2)
		case isTarget:
			out = io.MultiWriter(h, w)
		}
		if err := u.decode(br, out, dest); err != nil {
			return mapUnpackErr(err)
		}
		var b2sum []byte
		if hasB2 {
			sum := b2.Sum()
			b2sum = sum[:]
		}
		if err := checkFile(&cf.data, h.Sum32(), b2sum, sc); err != nil {
			return err
		}
	}
	return nil
}

// mapUnpackErr 把解包器错误映射为公开错误（保留哨兵兼容）。
func mapUnpackErr(err error) error {
	return err
}
