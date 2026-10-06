package rar

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"

	"github.com/ayasechan/unrar/internal/blake2s"
	"github.com/ayasechan/unrar/internal/rarcrypt"
)

// kdfEntry 是缓存的派生密钥。
type kdfEntry struct {
	key     []byte // AES 密钥（16 或 32 字节）。
	iv      []byte // 初始向量（16 字节）。
	hashKey []byte // RAR5 校验 MAC 密钥（32 字节，可空）。
	pswVal  []byte // RAR5 口令校验原值（32 字节，可空）。
}

// kdfCacheKey 区分算法与参数。
func kdfCacheKey(method string, password string, salt []byte, lg2 byte) string {
	return fmt.Sprintf("%s|%s|%x|%d", method, password, salt, lg2)
}

// kdf guarded by Reader.kdfMu.
func (r *Reader) kdfCached(key string, derive func() kdfEntry) kdfEntry {
	r.kdfMu.Lock()
	defer r.kdfMu.Unlock()
	if r.kdf == nil {
		r.kdf = map[string]kdfEntry{}
	}
	if e, ok := r.kdf[key]; ok {
		return e
	}
	e := derive()
	if len(r.kdf) > 16 {
		r.kdf = map[string]kdfEntry{}
	}
	r.kdf[key] = e
	return e
}

// resolvePassword 取文件口令。
func (r *Reader) resolvePassword(file string) (string, bool) {
	if len(r.opts.password) > 0 {
		return string(r.opts.password), true
	}
	if r.opts.passwordReader != nil {
		s, err := r.opts.passwordReader(file)
		if err != nil || s == "" {
			return "", false
		}
		return s, true
	}
	return "", false
}

// fileKeys4 派生 RAR4 文件密钥（AES-128）。
func (r *Reader) fileKeys4(fd *fileData, password string) (key, iv [16]byte) {
	ck := kdfCacheKey("rar4", password, fd.salt, 0)
	e := r.kdfCached(ck, func() kdfEntry {
		k, v := rarcrypt.KDF3(password, fd.salt)
		return kdfEntry{key: append([]byte(nil), k[:]...), iv: append([]byte(nil), v[:]...)}
	})
	copy(key[:], e.key)
	copy(iv[:], e.iv)
	return key, iv
}

// fileKeys5 派生 RAR5 文件密钥（AES-256），并做口令预检。
// 返回 hashKey（MAC 用）与 pswChecked（预检通过）。
func (r *Reader) fileKeys5(fd *fileData, password string) (key [32]byte, hashKey [32]byte, iv [16]byte, pswChecked bool, err error) {
	c := fd.crypt5
	if c.version > 0 {
		return key, hashKey, iv, false, fmt.Errorf("%w: RAR5 encryption version %d", ErrUnsupported, c.version)
	}
	ck := kdfCacheKey("rar5", password, c.salt[:], c.lg2Count)
	e := r.kdfCached(ck, func() kdfEntry {
		k, hk, pv, ok := rarcrypt.KDF5(password, c.salt[:], c.lg2Count)
		if !ok {
			return kdfEntry{}
		}
		// 注意：InitV 是 per-file 的，不进缓存。
		return kdfEntry{
			key:     append([]byte(nil), k[:]...),
			hashKey: append([]byte(nil), hk[:]...),
			pswVal:  append([]byte(nil), pv[:]...),
		}
	})
	if len(e.key) != 32 || len(e.pswVal) != 32 {
		return key, hashKey, iv, false, fmt.Errorf("%w: RAR5 KDF", ErrUnsupported)
	}
	copy(key[:], e.key)
	copy(hashKey[:], e.hashKey)
	copy(iv[:], c.initV[:])
	if c.usePswCheck && c.pswCheckOK {
		var pv [32]byte
		copy(pv[:], e.pswVal)
		if rarcrypt.FoldPswCheck(pv) != c.pswCheck {
			return key, hashKey, iv, false, ErrWrongPassword
		}
		pswChecked = true
	}
	return key, hashKey, iv, pswChecked, nil
}

// cryptStream 返回明文 pack 流与校验参数。
// 明文文件返回原始流；加密文件解密（无口令报 ErrEncrypted）。
func (r *Reader) cryptStream(f *File) (io.Reader, streamCheck, error) {
	var sc streamCheck
	raw := r.dataReader(&f.data)
	if !f.data.encrypted {
		return raw, sc, nil
	}
	password, ok := r.resolvePassword(f.Name)
	if !ok {
		return nil, sc, ErrEncrypted
	}
	switch r.Version {
	case 4:
		if f.data.unpVer < 29 {
			return nil, sc, fmt.Errorf("%w: encrypted RAR4 v%d", ErrUnsupported, f.data.unpVer)
		}
		key, iv := r.fileKeys4(&f.data, password)
		dec, err := newCBCReader(raw, key[:], iv[:])
		if err != nil {
			return nil, sc, err
		}
		return dec, sc, nil
	case 5:
		key, hk, iv, checked, err := r.fileKeys5(&f.data, password)
		if err != nil {
			return nil, sc, err
		}
		dec, err := newCBCReader(raw, key[:], iv[:])
		if err != nil {
			return nil, sc, err
		}
		sc.hashKey, sc.hasHashKey, sc.pswChecked = hk, true, checked
		return dec, sc, nil
	}
	return nil, sc, ErrUnsupported
}

// streamCheck 携带解密与校验上下文。
type streamCheck struct {
	hashKey    [32]byte
	hasHashKey bool
	pswChecked bool
}

// checkFile 校验解出数据的 CRC32/BLAKE2s。
// RAR5 加密：优先 MAC（置位时），否则 plain；部分版本多卷省略置位仍存 MAC 值，
// plain 失败时补试 MAC（两者皆为不可伪造的完整性证明）。
// 加密且无预检时的失败映射为 ErrWrongPassword，其余为 ErrChecksum。
func checkFile(fd *fileData, crcSum uint32, b2sum []byte, sc streamCheck) error {
	mismatch := ErrChecksum
	if fd.encrypted && !sc.pswChecked {
		mismatch = ErrWrongPassword
	}
	if fd.hasCRC {
		if crcSum == fd.crc {
			// 明文命中。
		} else if sc.hasHashKey && fd.crypt5.present && macCRC32(crcSum, sc.hashKey[:]) == fd.crc {
			// MAC 命中（UseHashKey 置位或多卷省略置位）。
		} else {
			return mismatch
		}
	}
	if len(fd.blake2) > 0 {
		if string(b2sum) == string(fd.blake2) {
			// 明文命中。
		} else if sc.hasHashKey && fd.crypt5.present && string(macBlake2(b2sum, sc.hashKey[:])) == string(fd.blake2) {
			// MAC 命中。
		} else {
			return mismatch
		}
	}
	return nil
}

// cbcReader 是 16 对齐分块的 CBC 解密流。
type cbcReader struct {
	src io.Reader
	dec *rarcrypt.Decrypter
	buf []byte // 待交付明文。
	tmp []byte // 读入密文。
	eof bool
	err error
}

func newCBCReader(src io.Reader, key, iv []byte) (*cbcReader, error) {
	dec, err := rarcrypt.NewDecrypter(key, iv)
	if err != nil {
		return nil, err
	}
	return &cbcReader{src: src, dec: dec, tmp: make([]byte, 32768)}, nil
}

func (c *cbcReader) Read(p []byte) (int, error) {
	if len(c.buf) == 0 {
		if c.eof {
			return 0, io.EOF
		}
		if c.err != nil {
			return 0, c.err
		}
		n, err := io.ReadFull(c.src, c.tmp)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				if n == 0 {
					return 0, io.EOF
				}
				if n%16 != 0 {
					c.err = io.ErrUnexpectedEOF
					return 0, c.err
				}
				c.eof = true // 16 对齐的尾块。
			} else {
				c.err = err
				return 0, err
			}
		}
		c.dec.Decrypt(c.tmp[:n])
		c.buf = append(c.buf[:0], c.tmp[:n]...)
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// verifier 在流式读取的同时算 CRC32（与可选 BLAKE2s），读尽时按 checkFile 校验。
type verifier struct {
	crc   hash.Hash32
	blake *blake2s.Hash
	fd    *fileData
	sc    streamCheck
	done  bool
	stash error
	r     io.Reader
}

func newVerifier(r io.Reader, fd *fileData, sc streamCheck) *verifier {
	v := &verifier{r: r, crc: crc32.NewIEEE(), fd: fd, sc: sc}
	if len(fd.blake2) > 0 {
		v.blake = blake2s.New()
	}
	return v
}

func (v *verifier) Read(p []byte) (int, error) {
	if v.done {
		if v.stash != nil {
			err := v.stash
			v.stash = nil
			return 0, err
		}
		return 0, io.EOF
	}
	n, err := v.r.Read(p)
	v.crc.Write(p[:n])
	if v.blake != nil {
		v.blake.Write(p[:n])
	}
	if err == io.EOF || (err == nil && n == 0) {
		v.done = true
		var b2 []byte
		if v.blake != nil {
			sum := v.blake.Sum()
			b2 = sum[:]
		}
		if verr := checkFile(v.fd, v.crc.Sum32(), b2, v.sc); verr != nil {
			v.stash = verr
		}
		if v.stash != nil {
			if n > 0 {
				return n, nil
			}
			return 0, v.stash
		}
	}
	if err == nil && n == 0 {
		return v.Read(p)
	}
	return n, err
}

// macCRC32 计算 HMAC 化的 CRC32 期望值（RAR5 UseHashKey）。
func macCRC32(crc uint32, hashKey []byte) uint32 {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], crc)
	d := hmacSHA256(hashKey, raw[:])
	var out uint32
	for i := range d {
		out ^= uint32(d[i]) << ((uint(i) & 3) * 8)
	}
	return out
}

// macBlake2 计算 HMAC 化的 BLAKE2s 期望值。
func macBlake2(digest, hashKey []byte) []byte {
	d := hmacSHA256(hashKey, digest)
	return d[:]
}

func hmacSHA256(key, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
