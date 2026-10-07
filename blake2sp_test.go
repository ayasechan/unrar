package rar

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ayasechan/unrar/internal/blake2sp"
	"github.com/ayasechan/unrar/internal/vint"
)

// 哈希夹具以官方 rar 5.5 构建（-ma5 -m5 -s- -ep，全显式开关）：
// t5htb.rar（-htb，BLAKE2sp 记录），t5htbp.rar（-htb -psecret，MAC 校验路径）。
const htbData = "blake2sp fixture data for hash verification\n"

func TestFileHashBLAKE2sp(t *testing.T) {
	r := openTestdata(t, "t5htb.rar")
	if r.Version != 5 {
		t.Fatalf("version = %d", r.Version)
	}
	if len(r.File) != 1 {
		t.Fatalf("File = %v", names(r))
	}
	f := r.File[0]
	if len(f.data.blake2) != blake2sp.Size {
		t.Fatalf("blake2 len = %d, want %d", len(f.data.blake2), blake2sp.Size)
	}
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("Read: %v (official -htb digest must verify)", err)
	}
	if string(got) != htbData {
		t.Fatalf("content = %q", got)
	}
}

func TestFileHashBLAKE2spPassword(t *testing.T) {
	// 无口令：压缩加密文件 Open 不报错，Read 时报 ErrEncrypted。
	r := openTestdata(t, "t5htbp.rar")
	rc, err := r.File[0].Open()
	if err != nil {
		if !errors.Is(err, ErrEncrypted) {
			t.Fatalf("Open = %v", err)
		}
		r.Close()
	} else {
		_, err = io.ReadAll(rc)
		rc.Close()
		r.Close()
		if !errors.Is(err, ErrEncrypted) {
			t.Fatalf("Read = %v, want ErrEncrypted", err)
		}
	}
	// 错口令：MAC 校验失败报口令错。
	r = openTestdata(t, "t5htbp.rar", WithPassword("wrong"))
	rc, err = r.File[0].Open()
	if err != nil {
		if !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("Open = %v", err)
		}
		r.Close()
		return
	}
	_, err = io.ReadAll(rc)
	rc.Close()
	r.Close()
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Read = %v, want ErrWrongPassword", err)
	}
	// 对口令：MAC 路径解出正确。
	r = openTestdata(t, "t5htbp.rar", WithPassword("secret"))
	rc, err = r.File[0].Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	r.Close()
	if err != nil || string(got) != htbData {
		t.Fatalf("content = %q, err = %v", got, err)
	}
}

// TestFileHashCorruptData 破坏 -htb 文件数据区：读尽时报 ErrChecksum。
func TestFileHashCorruptData(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "t5htb.rar"))
	if err != nil {
		t.Fatal(err)
	}
	r1, err := NewReader(MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": raw}})
	if err != nil {
		t.Fatal(err)
	}
	var seg segment
	for _, f := range r1.File {
		if !f.IsDir && len(f.data.segments) > 0 {
			seg = f.data.segments[0]
		}
	}
	r1.Close()
	if seg.size == 0 {
		t.Fatal("no data segment")
	}
	bad := append([]byte(nil), raw...)
	bad[seg.off] ^= 0xff
	r2, err := NewReader(MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": bad}})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	rc, err := r2.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); !errors.Is(err, ErrChecksum) {
		t.Fatalf("Read = %v, want ErrChecksum", err)
	}
	rc.Close()
}

// corruptHashByte 翻转 FILE 头 extra 中 0x02 摘要的一字节并重算头 CRC，
// 使扫描通过而摘要比对失败。
func corruptHashByte(t *testing.T, raw []byte) []byte {
	t.Helper()
	if !bytes_equal(raw[:8], rar5Mark) {
		t.Fatal("not RAR5")
	}
	pos := int64(len(rar5Mark))
	for {
		if pos+5 > int64(len(raw)) {
			t.Fatal("no FILE block")
		}
		sizeVal, sizeLen, err := vint.Decode(raw[pos+4:])
		if err != nil {
			t.Fatal(err)
		}
		total := int64(4+sizeLen) + int64(sizeVal)
		head := append([]byte(nil), raw[pos:pos+total]...)
		cur := 4 + sizeLen
		typ, n, err := vint.Decode(head[cur:])
		if err != nil {
			t.Fatal(err)
		}
		cur += n
		flags, n, err := vint.Decode(head[cur:])
		if err != nil {
			t.Fatal(err)
		}
		cur += n
		var extraSize uint64
		if flags&hflExtra != 0 {
			extraSize, n, err = vint.Decode(head[cur:])
			if err != nil {
				t.Fatal(err)
			}
			cur += n
		}
		var dataSize uint64
		if flags&hflData != 0 {
			dataSize, n, err = vint.Decode(head[cur:])
			if err != nil {
				t.Fatal(err)
			}
			cur += n
		}
		if typ == head5File && extraSize > 0 {
			// extra 区位于头尾：head[len(head)-extraSize:]。
			ex := head[len(head)-int(extraSize):]
			// 走查记录找 type 0x02。
			off := 0
			found := false
			for off < len(ex) {
				fsize, n1, err := vint.Decode(ex[off:])
				if err != nil || fsize == 0 {
					break
				}
				ftype, n2, err := vint.Decode(ex[off+n1:])
				if err != nil {
					break
				}
				bodyOff := off + n1 + n2
				bodyLen := int(fsize) - n2
				if bodyLen < 0 || bodyOff+bodyLen > len(ex) {
					break
				}
				if ftype == extraHash && bodyLen > 2 {
					// 摘要首字节在 body 内 vint 类型之后（ex 与 head 同底数组）。
					_, nn, err := vint.Decode(ex[bodyOff : bodyOff+bodyLen])
					if err != nil {
						t.Fatal(err)
					}
					ex[bodyOff+nn] ^= 0xff
					found = true
					break
				}
				off += n1 + int(fsize)
			}
			if !found {
				t.Fatal("no 0x02 hash record")
			}
			binary.LittleEndian.PutUint32(head[:4], crc32.Checksum(head[4:], crc32.IEEETable))
			out := append([]byte(nil), raw...)
			copy(out[pos:pos+total], head)
			_ = dataSize
			return out
		}
		pos += total + int64(dataSize)
	}
}

func bytes_equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestFileHashCorruptDigest 破坏摘要本身（头 CRC 已重算）：同样 ErrChecksum。
func TestFileHashCorruptDigest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "t5htb.rar"))
	if err != nil {
		t.Fatal(err)
	}
	bad := corruptHashByte(t, raw)
	r, err := NewReader(MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": bad}})
	if err != nil {
		t.Fatalf("scan must pass: %v", err)
	}
	defer r.Close()
	if len(r.File[0].data.blake2) != blake2sp.Size {
		t.Fatal("hash record lost")
	}
	rc, err := r.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); !errors.Is(err, ErrChecksum) {
		t.Fatalf("Read = %v, want ErrChecksum", err)
	}
	rc.Close()
}

// TestParseExtraHashValidation 未知哈希类型/长度不符直接丢弃，回落 CRC。
func TestParseExtraHashValidation(t *testing.T) {
	mkextra := func(typ uint64, body []byte) []byte {
		rec := vint.Encode(nil, uint64(len(vint.Encode(nil, typ))+len(body)))
		rec = vint.Encode(rec, typ)
		return append(rec, body...)
	}
	digest := make([]byte, blake2sp.Size)
	for i := range digest {
		digest[i] = byte(i)
	}
	hashBody := append(vint.Encode(nil, 0), digest...)
	// 合法 0x02 记录被收录。
	_, _, got := parseExtra5(mkextra(extraHash, hashBody))
	if len(got) != blake2sp.Size {
		t.Fatalf("valid hash dropped, len = %d", len(got))
	}
	// 未知类型丢弃。
	badType := append(vint.Encode(nil, 9), digest...)
	_, _, got = parseExtra5(mkextra(extraHash, badType))
	if len(got) != 0 {
		t.Fatalf("unknown hash type kept, len = %d", len(got))
	}
	// 长度不符丢弃。
	_, _, got = parseExtra5(mkextra(extraHash, append(vint.Encode(nil, 0), digest[:16]...)))
	if len(got) != 0 {
		t.Fatalf("short hash kept, len = %d", len(got))
	}
}
