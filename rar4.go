package rar

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io/fs"
	"time"

	"github.com/ayasechan/unrar/internal/rarcrypt"
)

// RAR4 签名与块类型/标志常量。
var rar4Mark = []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}

const (
	mhdVolume       = 0x0001
	mhdSolid        = 0x0008
	mhdNewNumbering = 0x0010
	mhdProtect      = 0x0040
	mhdPassword     = 0x0080
	mhdFirstVolume  = 0x0100

	earcNextVolume = 0x0001

	lhdSplitBefore = 0x0001
	lhdSplitAfter  = 0x0002
	lhdPassword    = 0x0004
	lhdSolid       = 0x0010
	lhdWindowMask  = 0x00e0
	lhdDirectory   = 0x00e0
	lhdLarge       = 0x0100
	lhdUnicode     = 0x0200
	lhdSalt        = 0x0400
	lhdExtTime     = 0x1000
	lhdLongBlock   = 0x8000
)

const (
	head3Main   = 0x73
	head3File   = 0x74
	head3EndArc = 0x7b
)

const (
	hostMSDOS = 0
	hostUNIX  = 3
)

// maxHeader4 单个 RAR4 头的上限，防止损坏数据导致超大分配。
const maxHeader4 = 2 << 20

// scan4 扫描 RAR4 归档，建立文件表。支持跨卷续流（分段拼接到同一 File）。
func (r *Reader) scan4() error {
	r.Version = 4
	var mark [7]byte
	if err := r.readFull(0, 0, mark[:]); err != nil {
		return err
	}
	for i := range rar4Mark {
		if mark[i] != rar4Mark[i] {
			return fmt.Errorf("rar: bad RAR4 signature: %w", ErrUnsupported)
		}
	}

	// MAIN 恒明文：口令位决定后续是否头加密。
	blk, err := r.readBlock4(0, int64(len(rar4Mark)))
	if err != nil {
		return err
	}
	if blk.typ == head3Main && blk.flags&mhdPassword != 0 {
		password, ok := r.resolvePassword(r.vols[0].name)
		if !ok {
			return ErrEncrypted
		}
		return r.scan4Encrypted(password)
	}

	var pending *File // splitAfter 未闭合的文件，等待后卷续流。
	hdrEncrypted := false

	return r.scan4vols(func(vi int, pos int64) (*block4, error) {
		return r.readBlock4(vi, pos)
	}, int64(len(rar4Mark)), pending, hdrEncrypted)
}

// scan4vols 逐卷扫描（读头函数可替换为头解密）。
func (r *Reader) scan4vols(readHeader func(vi int, pos int64) (*block4, error), start0 int64, pending *File, hdrEncrypted bool) error {
	for vi := range r.vols {
		// 每卷都以签名开头，头从签名后开始。
		pos := start0
		size := r.vols[vi].size
		ended := false
		for pos < size && !ended {
			blk, err := readHeader(vi, pos)
			if err != nil {
				if hdrEncrypted {
					return ErrEncrypted
				}
				return err
			}
			pos = blk.next
			switch blk.typ {
			case head3Main:
				if blk.flags&mhdPassword != 0 {
					hdrEncrypted = true
				}
				if blk.flags&mhdSolid != 0 {
					r.solidArc = true
				}
				if vi == 0 && blk.flags&mhdVolume != 0 && blk.flags&mhdFirstVolume == 0 {
					return fmt.Errorf("%w: not first volume", ErrMissingVolume)
				}
			case head3File:
				f, cont, end, err := r.parseFile4(vi, blk, pending)
				if err != nil {
					return err
				}
				if !cont {
					r.File = append(r.File, f)
				}
				if end {
					pending = nil
				} else if blk.flags&lhdSplitAfter != 0 {
					if cont {
						pending.data.continued = true
					} else {
						pending = f
					}
				}
			case head3EndArc:
				ended = true
				r.volNext = append(r.volNext, blk.flags&earcNextVolume != 0)
			default:
				// 注释/恢复记录/签名/子块等：按头长+数据长跳过。
			}
		}
		if !ended {
			r.volNext = append(r.volNext, false)
		}
	}
	return r.checkVolumes()
}

// scan4Encrypted 扫描头加密的 RAR4。
// MAIN 明文；其后每块为 [8B salt][16 对齐加密头]，各头独立 cipher。
func (r *Reader) scan4Encrypted(password string) error {
	readHeader := func(vi int, pos int64) (*block4, error) {
		if vi == 0 && pos == int64(len(rar4Mark)) {
			return r.readBlock4(vi, pos) // MAIN 明文。
		}
		return r.readBlock4Encrypted(vi, pos, password)
	}
	return r.scan4vols(readHeader, int64(len(rar4Mark)), nil, true)
}

// readBlock4Encrypted 读加密头：salt + 独立 CBC 解密。
func (r *Reader) readBlock4Encrypted(vol int, pos int64, password string) (*block4, error) {
	var salt [8]byte
	if err := r.readFull(vol, pos, salt[:]); err != nil {
		return nil, err
	}
	ck := kdfCacheKey("rar4h", password, salt[:], 0)
	e := r.kdfCached(ck, func() kdfEntry {
		k, v := rarcrypt.KDF3(password, salt[:])
		return kdfEntry{key: append([]byte(nil), k[:]...), iv: append([]byte(nil), v[:]...)}
	})
	dec, err := rarcrypt.NewDecrypter(e.key, e.iv)
	if err != nil {
		return nil, err
	}
	var first [16]byte
	if err := r.readFull(vol, pos+8, first[:]); err != nil {
		return nil, err
	}
	dec.Decrypt(first[:])
	headSize := int(binary.LittleEndian.Uint16(first[5:7]))
	if headSize < 7 || headSize > maxHeader4 {
		return nil, fmt.Errorf("rar: bad RAR4 block size %d: %w", headSize, ErrChecksum)
	}
	raw := make([]byte, headSize)
	copy(raw, first[:min(16, headSize)])
	padded := (headSize + 15) &^ 15
	rest := make([]byte, padded-16)
	if len(rest) > 0 {
		if err := r.readFull(vol, pos+8+16, rest); err != nil {
			return nil, err
		}
		dec.Decrypt(rest)
		copy(raw[16:], rest)
	}
	return r.parseBlock4(raw, vol, pos+8+int64(padded))
}

// block4 是一个 RAR4 块：头字段 + 头体 + 后续数据区位置。
type block4 struct {
	typ      byte
	flags    uint16
	headSize int
	dataSize uint32
	body     []byte // 头体（headSize-7 字节，含 ADD_SIZE）
	dataOff  int64  // 数据区起始
	next     int64  // 下一块起始
}

// readBlock4 在 (vol, pos) 读一个完整块头并校验 CRC。
func (r *Reader) readBlock4(vol int, pos int64) (*block4, error) {
	var base [7]byte
	if err := r.readFull(vol, pos, base[:]); err != nil {
		return nil, err
	}
	headSize := int(binary.LittleEndian.Uint16(base[5:7]))
	if headSize < 7 || headSize > maxHeader4 {
		return nil, fmt.Errorf("rar: bad RAR4 block size %d: %w", headSize, ErrChecksum)
	}
	raw := make([]byte, headSize)
	copy(raw, base[:])
	if err := r.readFull(vol, pos, raw); err != nil {
		return nil, err
	}
	return r.parseBlock4(raw, vol, pos+int64(headSize))
}

// parseBlock4 校验并解析头字节。dataOff 为数据区起始。
func (r *Reader) parseBlock4(raw []byte, vol int, dataOff int64) (*block4, error) {
	headSize := len(raw)
	if headSize < 7 || headSize > maxHeader4 {
		return nil, fmt.Errorf("rar: bad RAR4 block size %d: %w", headSize, ErrChecksum)
	}
	if uint16(crc32.Checksum(raw[2:], crc32.IEEETable)) != binary.LittleEndian.Uint16(raw[0:2]) {
		return nil, fmt.Errorf("rar: RAR4 header CRC mismatch: %w", ErrChecksum)
	}
	blk := &block4{
		typ:      raw[2],
		flags:    binary.LittleEndian.Uint16(raw[3:5]),
		headSize: headSize,
		body:     raw[7:],
	}
	if blk.flags&lhdLongBlock != 0 {
		if len(blk.body) < 4 {
			return nil, fmt.Errorf("rar: truncated RAR4 long block: %w", ErrChecksum)
		}
		blk.dataSize = binary.LittleEndian.Uint32(blk.body[0:4])
	}
	blk.dataOff = dataOff
	blk.next = blk.dataOff + int64(blk.dataSize)
	if blk.next < blk.dataOff || blk.next > r.vols[vol].size {
		// 数据区超出本卷：跨卷文件在卷尾是合法的（后卷续），
		// 这里只钳住本卷可读部分，续流由 pending 机制处理。
		// 非 splitAfter 却越界则为损坏。
		if blk.typ == head3File && blk.flags&lhdSplitAfter != 0 {
			blk.next = r.vols[vol].size
		} else {
			return nil, fmt.Errorf("rar: RAR4 block overruns volume: %w", ErrChecksum)
		}
	}
	return blk, nil
}

// parseFile4 解析 FILE_HEAD。cont 表示本次是后卷续流（已拼接到 pending）。
func (r *Reader) parseFile4(vol int, blk *block4, pending *File) (f *File, cont bool, end bool, err error) {
	p := blk.body
	need := func(n int) bool { return len(p) >= n }
	if !need(4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4) {
		return nil, false, false, fmt.Errorf("rar: truncated RAR4 file header: %w", ErrChecksum)
	}
	// body[0:4] 即 ADD_SIZE，已在 dataSize 中。
	lowUnp := binary.LittleEndian.Uint32(p[4:8])
	hostOS := p[8]
	fileCRC := binary.LittleEndian.Uint32(p[9:13])
	dosTime := binary.LittleEndian.Uint32(p[13:17])
	unpVer := p[17]
	method := int(p[18]) - 0x30
	nameSize := int(binary.LittleEndian.Uint16(p[19:21]))
	fileAttr := binary.LittleEndian.Uint32(p[21:25])
	p = p[25:]

	highPack, highUnp := uint32(0), uint32(0)
	large := blk.flags&lhdLarge != 0
	if large {
		if len(p) < 8 {
			return nil, false, false, fmt.Errorf("rar: truncated RAR4 large sizes: %w", ErrChecksum)
		}
		highPack = binary.LittleEndian.Uint32(p[0:4])
		highUnp = binary.LittleEndian.Uint32(p[4:8])
		p = p[8:]
	}
	if len(p) < nameSize {
		return nil, false, false, fmt.Errorf("rar: truncated RAR4 file name: %w", ErrChecksum)
	}
	nameField := p[:nameSize]
	p = p[nameSize:]

	var salt []byte
	if blk.flags&lhdSalt != 0 {
		if len(p) < 8 {
			return nil, false, false, fmt.Errorf("rar: truncated RAR4 salt: %w", ErrChecksum)
		}
		salt = append([]byte(nil), p[:8]...)
		p = p[8:]
	}

	mtime := dosTimeToTime(dosTime)
	if blk.flags&lhdExtTime != 0 {
		var ok bool
		p, mtime, ok = applyExtTime4(p, mtime)
		if !ok {
			return nil, false, false, fmt.Errorf("rar: truncated RAR4 ext time: %w", ErrChecksum)
		}
	}

	packSize := uint64(highPack)<<32 | uint64(blk.dataSize)
	unpSize := uint64(highUnp)<<32 | uint64(lowUnp)

	name := string(nameField)
	if blk.flags&lhdUnicode != 0 {
		name = decodeUnicodeName(nameField)
	}
	name = normalizeName(name)

	isDir := blk.flags&lhdWindowMask == lhdDirectory
	if unpVer < 20 && fileAttr&0x10 != 0 {
		isDir = true
	}
	var winSize uint64
	if !isDir {
		winSize = 0x10000 << ((uint(blk.flags) & lhdWindowMask) >> 5)
	}

	segSize := blk.next - blk.dataOff
	if blk.flags&lhdSplitBefore != 0 && pending != nil {
		pending.data.segments = append(pending.data.segments, segment{vol: vol, off: blk.dataOff, size: segSize})
		pending.data.continued = true
		// 续头 CRC：末卷为全文 CRC，中续为本卷 pack 段 CRC；后者为准。
		pending.data.crc = fileCRC
		pending.data.hasCRC = true
		return pending, true, blk.flags&lhdSplitAfter == 0, nil
	}

	f = &File{
		Name:         name,
		UnpackedSize: unpSize,
		Modified:     mtime,
		Mode:         mode4(hostOS, fileAttr, isDir),
		IsDir:        isDir,
		Encrypted:    blk.flags&lhdPassword != 0,
		Solid:        blk.flags&lhdSolid != 0,
		r:            r,
		data: fileData{
			method:      method,
			unpVer:      int(unpVer),
			packSize:    packSize,
			unpSize:     unpSize,
			crc:         fileCRC,
			hasCRC:      true,
			encrypted:   blk.flags&lhdPassword != 0,
			solid:       blk.flags&lhdSolid != 0,
			splitAfter:  blk.flags&lhdSplitAfter != 0,
			winSize:     winSize,
			sizeUnknown: !large && lowUnp == 0xffffffff,
			salt:        salt,
		},
	}
	if segSize > 0 {
		f.data.segments = append(f.data.segments, segment{vol: vol, off: blk.dataOff, size: segSize})
	}
	return f, false, blk.flags&lhdSplitAfter == 0, nil
}

// applyExtTime4 消费 EXT_TIME 区，返回剩余字节与修正后的 mtime。
// 版式：flags u16；mtime/ctime/atime/arctime 各占 4bit rmode；
// rmode&8 表示存在；非 mtime 项先跟 4 字节 DosTime；
// rmode&4 给 mtime 加 1 秒；低 2bit 为大端 100ns 余数字节数。
func applyExtTime4(p []byte, mtime time.Time) ([]byte, time.Time, bool) {
	if len(p) < 2 {
		return p, mtime, false
	}
	flags := binary.LittleEndian.Uint16(p[:2])
	p = p[2:]
	for i := 0; i < 4; i++ {
		rmode := (flags >> ((3 - i) * 4)) & 0xf
		if rmode&8 == 0 {
			continue
		}
		if i != 0 {
			if len(p) < 4 {
				return p, mtime, false
			}
			p = p[4:]
		} else if rmode&4 != 0 {
			mtime = mtime.Add(time.Second)
		}
		count := int(rmode & 3)
		if len(p) < count {
			return p, mtime, false
		}
		if i == 0 && count > 0 {
			var v uint32
			for j := 0; j < count; j++ {
				v = v<<8 | uint32(p[j])
			}
			mtime = mtime.Add(time.Duration(uint64(v) * 100))
		}
		p = p[count:]
	}
	return p, mtime, true
}

// mode4 由 HOST_OS 与属性推导文件模式。
func mode4(hostOS byte, attr uint32, isDir bool) fs.FileMode {
	if hostOS == hostUNIX {
		m := fs.FileMode(attr & 0o7777)
		switch attr & 0o170000 {
		case 0o040000:
			m |= fs.ModeDir
		case 0o120000:
			m |= fs.ModeSymlink
		}
		if isDir {
			m |= fs.ModeDir
		}
		return m
	}
	if isDir || attr&0x10 != 0 {
		return fs.ModeDir | 0o555
	}
	if attr&0x01 != 0 {
		return 0o444
	}
	return 0o666
}

// normalizeName 统一分隔符为 '/'。
func normalizeName(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			out = append(out, '/')
		} else {
			out = append(out, s[i])
		}
	}
	return string(out)
}
