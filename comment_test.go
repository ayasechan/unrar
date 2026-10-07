package rar

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ayasechan/unrar/internal/vint"
)

// 注释夹具均以官方 rar 5.5 构建，全显式开关（-ma4/-ma5 -m0 -s- -ep，注释经 -z 注入，口令 -p/-hp）：
// t4cmt/t5cmt（ASCII 注释），t4cmtu/t5cmtu（CJK 注释），
// t4cmtp/t5cmtp（-p 数据加密），t4cmthp/t5cmthp（-hp 头加密，口令 secret）。
const (
	commentASCII = "ARCHIVE COMMENT LINE1\nLINE2 ascii only"
	commentCJK   = "中文注释测试"
	commentFile  = "hello.txt"
	commentData  = "comment fixture data\n"
)

func checkCommentArchive(t *testing.T, arc string, version int, wantComment string) {
	t.Helper()
	r := openTestdata(t, arc)
	if r.Version != version {
		t.Fatalf("%s version = %d, want %d", arc, r.Version, version)
	}
	if r.Comment != wantComment {
		t.Fatalf("%s Comment = %q, want %q", arc, r.Comment, wantComment)
	}
	// CMT 服务块不得进入文件表。
	if len(r.File) != 1 || r.File[0].Name != commentFile {
		t.Fatalf("%s File = %v, want [%s]", arc, names(r), commentFile)
	}
	f := r.File[0]
	if f.IsDir {
		t.Fatalf("%s %q is dir", arc, commentFile)
	}
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("%s Open: %v", arc, err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("%s Read: %v", arc, err)
	}
	if string(got) != commentData {
		t.Fatalf("%s content = %q, want %q", arc, got, commentData)
	}
}

func TestCommentArchive(t *testing.T) {
	checkCommentArchive(t, "t4cmt.rar", 4, commentASCII)
	checkCommentArchive(t, "t5cmt.rar", 5, commentASCII)
}

func TestCommentUnicode(t *testing.T) {
	checkCommentArchive(t, "t4cmtu.rar", 4, commentCJK)
	checkCommentArchive(t, "t5cmtu.rar", 5, commentCJK)
}

func TestCommentDataEncrypted(t *testing.T) {
	for _, arc := range []string{"t4cmtp.rar", "t5cmtp.rar"} {
		r := openTestdata(t, arc)
		// 数据加密不影响归档注释明文可见。
		if r.Comment != commentASCII {
			t.Fatalf("%s Comment = %q, want %q", arc, r.Comment, commentASCII)
		}
		if _, err := r.File[0].Open(); !errors.Is(err, ErrEncrypted) {
			t.Fatalf("%s Open = %v, want ErrEncrypted", arc, err)
		}
		r.Close()
	}
	for _, arc := range []string{"t4cmtp.rar", "t5cmtp.rar"} {
		r := openTestdata(t, arc, WithPassword("secret"))
		if r.Comment != commentASCII {
			t.Fatalf("%s Comment = %q, want %q", arc, r.Comment, commentASCII)
		}
		rc, err := r.File[0].Open()
		if err != nil {
			t.Fatalf("%s Open: %v", arc, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || string(got) != commentData {
			t.Fatalf("%s content = %q, err = %v", arc, got, err)
		}
		r.Close()
	}
}

func TestCommentHeaderEncrypted(t *testing.T) {
	for _, arc := range []string{"t4cmthp.rar", "t5cmthp.rar"} {
		if _, err := OpenReader(filepath.Join("testdata", arc)); !errors.Is(err, ErrEncrypted) {
			t.Fatalf("OpenReader(%s) = %v, want ErrEncrypted", arc, err)
		}
		r := openTestdata(t, arc, WithPassword("secret"))
		if r.Comment != commentASCII {
			t.Fatalf("%s Comment = %q, want %q", arc, r.Comment, commentASCII)
		}
		rc, err := r.File[0].Open()
		if err != nil {
			t.Fatalf("%s Open: %v", arc, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || string(got) != commentData {
			t.Fatalf("%s content = %q, err = %v", arc, got, err)
		}
		r.Close()
	}
}

// TestCommentCorruptSilent 注释区损坏只留空，不影响归档打开与文件解出。
func TestCommentCorruptSilent(t *testing.T) {
	for _, arc := range []string{"t4cmt.rar", "t5cmt.rar"} {
		raw, err := os.ReadFile(filepath.Join("testdata", arc))
		if err != nil {
			t.Fatal(err)
		}
		mem := func(b []byte) VolumeSet {
			return MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": b}}
		}
		r1, err := NewReader(mem(raw))
		if err != nil {
			t.Fatalf("%s: %v", arc, err)
		}
		if r1.cmtFile == nil || len(r1.cmtFile.data.segments) == 0 {
			t.Fatalf("%s: no comment segment", arc)
		}
		seg := r1.cmtFile.data.segments[0]
		r1.Close()
		bad := append([]byte(nil), raw...)
		bad[seg.off] ^= 0xff
		r2, err := NewReader(mem(bad))
		if err != nil {
			t.Fatalf("%s corrupt: OpenReader: %v", arc, err)
		}
		defer r2.Close()
		if r2.Comment != "" {
			t.Fatalf("%s corrupt: Comment = %q, want empty", arc, r2.Comment)
		}
		rc, err := r2.File[0].Open()
		if err != nil {
			t.Fatalf("%s corrupt: Open: %v", arc, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || string(got) != commentData {
			t.Fatalf("%s corrupt: content = %q, err = %v", arc, got, err)
		}
	}
}

func TestCommentTextConv(t *testing.T) {
	if got := cutCommentString([]byte("ab\x00cd")); got != "ab" {
		t.Fatalf("cut = %q", got)
	}
	if got := cutCommentString([]byte("ab")); got != "ab" {
		t.Fatalf("cut = %q", got)
	}
	// UTF-16LE：ASCII + CJK + 代理对 + 截 NUL + 孤立项。
	raw := []byte{'h', 0, 0x2d, 0x4e, 0, 0, 'x', 0}
	if got := utf16LEString(raw); got != "h\u4e2d" {
		t.Fatalf("utf16 NUL cut = %q", got)
	}
	// U+20000（代理对）与孤立高代理。
	raw = []byte{0x40, 0xd8, 0x00, 0xdc, 0x00, 0xd8}
	if got := utf16LEString(raw); got != "\U00020000\ufffd" {
		t.Fatalf("utf16 surrogate = %q", got)
	}
	if got := commentText4([]byte("ab\x00"), false); got != "ab" {
		t.Fatalf("ansi = %q", got)
	}
}

// block5Raw 组最小 RAR5 块：CRC32 + vint(头长) + 内容。
func block5Raw(typ uint64, flags uint64, body []byte, extra []byte, dataSize uint64, hasData bool) []byte {
	content := vint.Encode(nil, typ)
	content = vint.Encode(content, flags)
	if extra != nil {
		content = vint.Encode(content, uint64(len(extra)))
	}
	if hasData {
		content = vint.Encode(content, dataSize)
	}
	content = append(content, body...)
	content = append(content, extra...)
	size := vint.Encode(nil, uint64(len(content)))
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, crc32.Checksum(append(size, content...), crc32.IEEETable))
	out = append(out, size...)
	return append(out, content...)
}

// tinyRAR5Service 造仅含 MAIN + SERVICE(CMT,stored) + ENDARC 的最小 RAR5。
func tinyRAR5Service(t *testing.T, unpSize uint64, data []byte) []byte {
	t.Helper()
	var arc []byte
	arc = append(arc, rar5Mark...)
	arc = append(arc, block5Raw(head5Main, 0, nil, nil, 0, false)...)
	body := vint.Encode(nil, fhflCRC32) // 有 DATA_CRC32。
	body = vint.Encode(body, unpSize)
	body = vint.Encode(body, 0) // attr
	var dcrc [4]byte
	binary.LittleEndian.PutUint32(dcrc[:], crc32.ChecksumIEEE(data))
	body = append(body, dcrc[:]...)
	body = vint.Encode(body, 0) // compInfo：store。
	body = vint.Encode(body, 1) // host：unix。
	body = vint.Encode(body, uint64(len(cmtServiceName)))
	body = append(body, cmtServiceName...)
	arc = append(arc, block5Raw(head5Service, hflData, body, nil, uint64(len(data)), true)...)
	arc = append(arc, data...)
	arc = append(arc, block5Raw(head5EndArc, 0, nil, nil, 0, false)...)
	return arc
}

func TestCommentSyntheticStored(t *testing.T) {
	arc := tinyRAR5Service(t, 3, []byte{'h', 'i', 0})
	r, err := NewReader(MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": arc}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Comment != "hi" {
		t.Fatalf("Comment = %q, want %q", r.Comment, "hi")
	}
	if len(r.File) != 0 {
		t.Fatalf("File = %v, want empty", names(r))
	}
}

// TestCommentTooLarge 超 16MB 声明的注释直接留空，不分配。
func TestCommentTooLarge(t *testing.T) {
	arc := tinyRAR5Service(t, maxCommentSize+1, []byte{'h', 'i', 0})
	r, err := NewReader(MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": arc}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Comment != "" {
		t.Fatalf("Comment = %q, want empty", r.Comment)
	}
}
