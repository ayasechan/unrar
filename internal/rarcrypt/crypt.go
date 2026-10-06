// Package rarcrypt 提供 RAR 口令编码、KDF 与 AES-CBC 解密。
package rarcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
)

// MaxPasswordRAR 是 RAR 口令的 wchar 上限（含尾零 128）。
const MaxPasswordRAR = 128

// TruncatePassword 按 wchar（rune）截断到 127 字符。
func TruncatePassword(s string) string {
	r := []rune(s)
	if len(r) >= MaxPasswordRAR {
		r = r[:MaxPasswordRAR-1]
	}
	return string(r)
}

// WideToRaw 模拟 WideToRaw：rune 取低 16 位小端（非 BMP 截断亦一致）。
func WideToRaw(s string) []byte {
	r := []rune(TruncatePassword(s))
	out := make([]byte, 0, len(r)*2)
	for _, c := range r {
		u := uint16(c & 0xffff)
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// WideToUTF8 模拟 WideToUtf：标准 UTF-8（Linux wchar 即码点）。
func WideToUTF8(s string) []byte {
	return []byte(TruncatePassword(s))
}

// hmacSHA256 标准 HMAC-SHA-256。
func hmacSHA256(key, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// PBKDF2-HMAC-SHA256（RAR5 变体）：Key 跑 count 轮，V1/V2 各续 16 轮，
// 累加器 Fn 跨三段连续异或。
func pbkdf2(pwd, salt []byte, count uint) (key, v1, v2 [32]byte) {
	var saltData [68]byte
	copy(saltData[:], salt)
	saltData[len(salt)] = 0
	saltData[len(salt)+1] = 0
	saltData[len(salt)+2] = 0
	saltData[len(salt)+3] = 1
	u1 := hmacSHA256(pwd, saltData[:len(salt)+4])
	fn := u1
	rounds := []uint{count - 1, 16, 16}
	outs := []*[32]byte{&key, &v1, &v2}
	var u2 [32]byte
	for i := 0; i < 3; i++ {
		for j := uint(0); j < rounds[i]; j++ {
			u2 = hmacSHA256(pwd, u1[:])
			u1 = u2
			for k := range fn {
				fn[k] ^= u1[k]
			}
		}
		*outs[i] = fn
	}
	return key, v1, v2
}

// KDF5 由口令派生 RAR5 密钥三元组。lg2 为 PBKDF2 轮数对数（count=1<<lg2）。
func KDF5(password string, salt []byte, lg2 byte) (key, hashKey, pswCheckValue [32]byte, ok bool) {
	if lg2 > 24 {
		return key, hashKey, pswCheckValue, false
	}
	pwd := WideToUTF8(password)
	key, hashKey, pswCheckValue = pbkdf2(pwd, salt, 1<<lg2)
	wipe(pwd)
	return key, hashKey, pswCheckValue, true
}

// FoldPswCheck 把 32 字节校验值折叠为 8 字节。
func FoldPswCheck(v [32]byte) [8]byte {
	var out [8]byte
	for i := range v {
		out[i%8] ^= v[i]
	}
	return out
}

// KDF3 由口令派生 RAR3.0 AES-128 密钥与 IV。
func KDF3(password string, salt []byte) (key, iv [16]byte) {
	raw := WideToRaw(password)
	raw = append(raw, salt...)
	// 注意：rar29 变体原地修改 raw。
	buf := append([]byte(nil), raw...)
	wipe(raw)
	var c sha1ctx
	sha1Init(&c)
	const rounds = 0x40000
	var digest [5]uint32
	for i := uint(0); i < rounds; i++ {
		sha1ProcessRar29(&c, buf)
		var num [3]byte
		num[0], num[1], num[2] = byte(i), byte(i>>8), byte(i>>16)
		sha1Process(&c, num[:])
		if i%(rounds/16) == 0 {
			t := c
			d := sha1Done(&t)
			iv[i/(rounds/16)] = byte(d[4])
		}
	}
	digest = sha1Done(&c)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			key[i*4+j] = byte(digest[i] >> (uint(j) * 8))
		}
	}
	wipe(buf)
	return key, iv
}

// Decrypter 是 AES-CBC 流解密器（跨调用保持链）。
type Decrypter struct {
	mode cipher.BlockMode
}

// NewDecrypter 构造解密器（key 16/32 字节，iv 16 字节）。
func NewDecrypter(key, iv []byte) (*Decrypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != 16 {
		return nil, errBadIV
	}
	return &Decrypter{mode: cipher.NewCBCDecrypter(block, iv)}, nil
}

// Decrypt 原地解密 16 对齐数据。
func (d *Decrypter) Decrypt(data []byte) {
	d.mode.CryptBlocks(data, data)
}

type errString string

func (e errString) Error() string { return string(e) }

const errBadIV = errString("rarcrypt: bad IV length")

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
