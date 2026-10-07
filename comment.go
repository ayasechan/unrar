package rar

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"

	"github.com/ayasechan/unrar/internal/bitio"
	"github.com/ayasechan/unrar/internal/blake2s"
)

// cmtServiceName 是归档注释服务块名（RAR4 NEW_SUB / RAR5 SERVICE 通用）。
const cmtServiceName = "CMT"

// cmtUnicodeFlag 是 RAR4 子块标志（复用 ATTR 字段）中“内容为 UTF-16LE”的位。
const cmtUnicodeFlag = 0x00000001

// maxCommentSize 是注释解出上限，与官方读取侧一致；超限视为无注释。
const maxCommentSize = 0x1000000

// subFlagsOf4 取 RAR4 块的 ATTR/子块标志字段（位于头体固定偏移，与 large 无关）。
func subFlagsOf4(blk *block4) uint32 {
	if len(blk.body) < 25 {
		return 0
	}
	return binary.LittleEndian.Uint32(blk.body[21:25])
}

// finishComment 解码扫描期记录的 CMT 注释并填入 Reader.Comment。
// 注释是元数据：任何失败（损坏、超限、未知方法、缺口令）都留空，不影响归档打开。
func (r *Reader) finishComment() {
	if r.cmtFile == nil {
		return
	}
	raw, err := r.decodeCommentData(&r.cmtFile.data)
	if err != nil {
		return
	}
	if r.Version == 4 {
		r.Comment = commentText4(raw, r.cmtUnicode)
	} else {
		r.Comment = cutCommentString(raw)
	}
}

// decodeCommentData 单次解出注释字节流，状态全新（不复用固实链）。
func (r *Reader) decodeCommentData(fd *fileData) ([]byte, error) {
	if !fd.sizeUnknown && fd.unpSize > maxCommentSize {
		return nil, ErrUnsupported
	}
	cf := &File{r: r, Name: cmtServiceName, data: *fd}
	cf.data.solid = false
	var rc io.ReadCloser
	var err error
	switch {
	case fd.method == 0:
		if fd.splitAfter && !fd.continued {
			return nil, ErrMissingVolume
		}
		var stream io.Reader
		var sc streamCheck
		if stream, sc, err = r.cryptStream(cf); err != nil {
			return nil, err
		}
		if !fd.sizeUnknown {
			stream = io.LimitReader(stream, int64(fd.unpSize))
		}
		rc = io.NopCloser(newVerifier(stream, fd, sc))
	case r.Version == 4 && fd.unpVer == 29:
		rc, err = r.openComment29(cf)
	case r.Version == 5 && fd.unpVer == 0:
		rc, err = r.openComment50(cf)
	default:
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	out, err := io.ReadAll(io.LimitReader(rc, maxCommentSize+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(out)) > maxCommentSize {
		return nil, ErrUnsupported
	}
	return out, nil
}

// openComment29 解单段 RAR4 注释流（全新解包状态）。
func (r *Reader) openComment29(cf *File) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(r.decodeOne29(cf, pw))
	}()
	return pr, nil
}

// decodeOne29 解单个 RAR4 文件数据（注释用，不走固实链）。
func (r *Reader) decodeOne29(cf *File, w io.Writer) error {
	u := &unpack29{}
	if err := u.init(cf.data.winSize, false); err != nil {
		return err
	}
	stream, sc, err := r.cryptStream(cf)
	if err != nil {
		return err
	}
	br := bitio.NewReader(stream)
	dest := int64(cf.data.unpSize)
	if cf.data.sizeUnknown {
		dest = -1
	}
	h := crc32.NewIEEE()
	out := io.MultiWriter(h, w)
	var b2 *blake2s.Hash
	if len(cf.data.blake2) > 0 {
		b2 = blake2s.New()
		out = io.MultiWriter(h, b2, w)
	}
	if err := u.decode(br, out, dest); err != nil {
		return mapUnpackErr(err)
	}
	var b2sum []byte
	if b2 != nil {
		sum := b2.Sum()
		b2sum = sum[:]
	}
	return checkFile(&cf.data, h.Sum32(), b2sum, sc)
}

// openComment50 解单段 RAR5 注释流（全新解包状态）。
func (r *Reader) openComment50(cf *File) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(r.decodeOne50(cf, pw))
	}()
	return pr, nil
}

// decodeOne50 解单个 RAR5 文件数据（注释用，不走固实链）。
func (r *Reader) decodeOne50(cf *File, w io.Writer) error {
	u := &unpack50{}
	if err := u.init(cf.data.winSize, false, false); err != nil {
		return err
	}
	stream, sc, err := r.cryptStream(cf)
	if err != nil {
		return err
	}
	br := bitio.NewReader(stream)
	dest := int64(cf.data.unpSize)
	if cf.data.sizeUnknown {
		dest = -1
	}
	h := crc32.NewIEEE()
	out := io.MultiWriter(h, w)
	var b2 *blake2s.Hash
	if len(cf.data.blake2) > 0 {
		b2 = blake2s.New()
		out = io.MultiWriter(h, b2, w)
	}
	if err := u.decode(br, out, dest); err != nil {
		return mapUnpackErr(err)
	}
	var b2sum []byte
	if b2 != nil {
		sum := b2.Sum()
		b2sum = sum[:]
	}
	return checkFile(&cf.data, h.Sum32(), b2sum, sc)
}

// commentText4 转 RAR4 注释字节为串：unicode 标志置位时内容为 UTF-16LE，
// 否则为 ANSI 原字节直透；坏单元替换为 U+FFFD，不报错。
func commentText4(raw []byte, unicode bool) string {
	if unicode {
		return utf16LEString(raw)
	}
	return cutCommentString(raw)
}

// cutCommentString 按 C 语义截首个 NUL（含官方创建时追加的尾零）。
func cutCommentString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// utf16LEString 解 UTF-16LE：截首个宽 NUL，孤立代理项替换为 U+FFFD。
func utf16LEString(b []byte) string {
	b = b[:len(b)&^1]
	out := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := uint32(b[i]) | uint32(b[i+1])<<8
		if u == 0 {
			break
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+3 < len(b) {
				lo := uint32(b[i+2]) | uint32(b[i+3])<<8
				if lo >= 0xdc00 && lo <= 0xdfff {
					out = append(out, rune(0x10000+(u-0xd800)<<10+(lo-0xdc00)))
					i += 2
					continue
				}
			}
			out = append(out, 0xfffd)
			continue
		}
		if u >= 0xdc00 && u <= 0xdfff {
			out = append(out, 0xfffd)
			continue
		}
		out = append(out, rune(u))
	}
	return string(out)
}
