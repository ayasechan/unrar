package rar

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"time"

	"github.com/ayasechan/unrar/internal/blake2sp"
	"github.com/ayasechan/unrar/internal/rarcrypt"
	"github.com/ayasechan/unrar/internal/vint"
)

// RAR5 签名与块类型/标志常量。
var rar5Mark = []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}

const (
	hflExtra       = 0x0001
	hflData        = 0x0002
	hflSkipUnknown = 0x0004
	hflSplitBefore = 0x0008
	hflSplitAfter  = 0x0010
	hflChild       = 0x0020

	mhflVolume    = 0x0001
	mhflVolNumber = 0x0002
	mhflSolid     = 0x0004

	fhflDirectory  = 0x0001
	fhflUtime      = 0x0002
	fhflCRC32      = 0x0004
	fhflUnpUnknown = 0x0008

	ehflNextVolume = 0x0001

	fciSolid = 0x40

	host5Windows = 0
	host5Unix    = 1
)

const (
	head5Main    = 0x01
	head5File    = 0x02
	head5Service = 0x03
	head5Crypt   = 0x04
	head5EndArc  = 0x05
)

// extra 记录类型（FHEXTRA_*）。
const (
	extraCrypt = 0x01
	extraHash  = 0x02
	extraHTime = 0x03
)

// HTIME 标志。
const (
	htimeUnixTime = 0x01
	htimeMTime    = 0x02
	htimeUnixNS   = 0x10
)

// maxHeader5 单个 RAR5 头的上限。
const maxHeader5 = 8 << 20

// scan5 扫描 RAR5 归档，建立文件表。支持跨卷续流与头加密。
func (r *Reader) scan5() error {
	r.Version = 5
	var pending *File
	hdrEncrypted := false
	decrypt := false
	var arcKey [32]byte

	readHeader := func(vi int, pos int64) (*block5, error) {
		if !decrypt {
			return r.readBlock5(vi, pos)
		}
		return r.readBlock5Encrypted(vi, pos, arcKey)
	}

	for vi := range r.vols {
		// 每卷都以签名开头，头从签名后开始。
		pos := int64(len(rar5Mark))
		size := r.vols[vi].size
		ended := false
		for pos < size && !ended {
			blk, err := readHeader(vi, pos)
			if err != nil {
				if !decrypt && r.arcCrypt5 != nil {
					// CRYPT 之后读失败：按头加密处理（失败形态不限 CRC）。
					password, ok := r.resolvePassword(r.vols[0].name)
					if !ok {
						return ErrEncrypted
					}
					key, _, _, err := r.arcKeys5(password)
					if err != nil {
						return err
					}
					arcKey = key
					decrypt = true
					blk, err = readHeader(vi, pos)
					if err != nil {
						return ErrEncrypted
					}
				} else if hdrEncrypted || decrypt {
					return ErrEncrypted
				} else {
					return err
				}
			}
			pos = blk.next
			switch blk.typ {
			case head5Crypt:
				hdrEncrypted = true
				r.parseArcCrypt5(blk)
			case head5Main:
				// body 首 vint 为 ArcFlags，其后可能有卷号。
				if flags, n, err := vint.Decode(blk.body); err == nil {
					if flags&mhflSolid != 0 {
						r.solidArc = true
					}
					if flags&mhflVolume != 0 {
						volNum := uint64(0)
						if flags&mhflVolNumber != 0 {
							rest := blk.body[n:]
							if vn, _, verr := vint.Decode(rest); verr == nil {
								volNum = vn
							} else {
								return fmt.Errorf("rar: bad RAR5 volnumber: %w", ErrChecksum)
							}
						}
						if vi == 0 && volNum != 0 {
							return fmt.Errorf("%w: not first volume", ErrMissingVolume)
						}
					}
				}
			case head5File:
				f, cont, end, err := r.parseFile5(vi, blk, pending)
				if err != nil {
					return err
				}
				if !cont {
					r.File = append(r.File, f)
				}
				if end {
					pending = nil
				} else if blk.splitAfter {
					if cont {
						pending.data.continued = true
					} else {
						pending = f
					}
				}
			case head5EndArc:
				ended = true
				next := false
				if flags, _, err := vint.Decode(blk.body); err == nil && flags&ehflNextVolume != 0 {
					next = true
				}
				r.volNext = append(r.volNext, next)
			case head5Service:
				// 服务块与文件头同布局；名为 CMT 的是归档注释，其余跳过。
				f, cont, end, err := r.parseFile5(vi, blk, r.cmtPending)
				if err != nil {
					return err
				}
				if !cont && f.Name == cmtServiceName && r.cmtFile == nil {
					r.cmtFile = f
				}
				if end {
					r.cmtPending = nil
				} else if blk.splitAfter {
					if cont {
						r.cmtPending.data.continued = true
					} else {
						r.cmtPending = f
					}
				}
			default:
				// MAIN：位置已由块长推进，无需处理。
			}
		}
		if !ended {
			r.volNext = append(r.volNext, false)
		}
	}
	if err := r.checkVolumes(); err != nil {
		return err
	}
	r.finishComment()
	return nil
}

// block5 是一个 RAR5 块。
type block5 struct {
	typ        uint64
	flags      uint64
	extraSize  uint64
	dataSize   uint64
	headSize   int
	body       []byte // type 之后、extra 之前的字段区
	extra      []byte // 头尾 extra 区
	splitAfter bool
	dataOff    int64
	next       int64
}

// readBlock5 在 (vol, pos) 读一个完整块头并校验 CRC。
func (r *Reader) readBlock5(vol int, pos int64) (*block5, error) {
	raw, err := r.fetchBlock5(vol, pos)
	if err != nil {
		return nil, err
	}
	return r.parseBlock5(raw, vol, pos+int64(len(raw)))
}

// fetchBlock5 读明文头字节。
func (r *Reader) fetchBlock5(vol int, pos int64) ([]byte, error) {
	// 先读 CRC + 最多 10 字节 vint，确定头长。
	var prefix [14]byte
	srSize := int64(len(prefix))
	if pos+srSize > r.vols[vol].size {
		srSize = r.vols[vol].size - pos
	}
	if srSize < 5 {
		return nil, fmt.Errorf("rar: truncated RAR5 header: %w", io.ErrUnexpectedEOF)
	}
	if err := r.readFull(vol, pos, prefix[:srSize]); err != nil {
		return nil, err
	}
	sizeVal, sizeLen, err := vint.Decode(prefix[4:srSize])
	if err != nil {
		return nil, fmt.Errorf("rar: bad RAR5 header size: %w", ErrChecksum)
	}
	total := 4 + int64(sizeLen) + int64(sizeVal)
	if sizeVal == 0 || total < 7 || total > maxHeader5 {
		return nil, fmt.Errorf("rar: bad RAR5 block size %d: %w", sizeVal, ErrChecksum)
	}
	raw := make([]byte, total)
	if err := r.readFull(vol, pos, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// parseBlock5 校验并解析头字节。dataOff 为数据区起始。
func (r *Reader) parseBlock5(raw []byte, vol int, dataOff int64) (*block5, error) {
	total := int64(len(raw))
	var err error
	sizeLen := 0
	if _, sizeLen, err = vint.Decode(raw[4:]); err != nil {
		return nil, fmt.Errorf("rar: bad RAR5 header size: %w", ErrChecksum)
	}
	if crc32.Checksum(raw[4:], crc32.IEEETable) != binary.LittleEndian.Uint32(raw[0:4]) {
		return nil, fmt.Errorf("rar: RAR5 header CRC mismatch: %w", ErrChecksum)
	}
	blk := &block5{headSize: int(total)}
	cur := raw[4+sizeLen:]
	getV := func() (uint64, error) {
		v, n, err := vint.Decode(cur)
		if err != nil {
			return 0, fmt.Errorf("rar: truncated RAR5 header: %w", ErrChecksum)
		}
		cur = cur[n:]
		return v, nil
	}
	if blk.typ, err = getV(); err != nil {
		return nil, err
	}
	if blk.flags, err = getV(); err != nil {
		return nil, err
	}
	if blk.flags&hflExtra != 0 {
		if blk.extraSize, err = getV(); err != nil {
			return nil, err
		}
		if blk.extraSize > uint64(len(cur)) {
			return nil, fmt.Errorf("rar: bad RAR5 extra size: %w", ErrChecksum)
		}
	}
	if blk.flags&hflData != 0 {
		if blk.dataSize, err = getV(); err != nil {
			return nil, err
		}
	}
	bodyEnd := len(cur) - int(blk.extraSize)
	if bodyEnd < 0 {
		return nil, fmt.Errorf("rar: bad RAR5 extra size: %w", ErrChecksum)
	}
	blk.body = cur[:bodyEnd]
	blk.extra = cur[bodyEnd:]
	blk.splitAfter = blk.flags&hflSplitAfter != 0
	blk.dataOff = dataOff
	blk.next = blk.dataOff + int64(blk.dataSize)
	if blk.next < blk.dataOff || (blk.next > r.vols[vol].size && !(blk.typ == head5File && blk.splitAfter)) {
		return nil, fmt.Errorf("rar: RAR5 block overruns volume: %w", ErrChecksum)
	}
	if blk.next > r.vols[vol].size {
		blk.next = r.vols[vol].size
	}
	return blk, nil
}

// parseArcCrypt5 解析 CRYPT 块的头加密参数。
func (r *Reader) parseArcCrypt5(blk *block5) {
	cur := blk.body
	getV := func() (uint64, bool) {
		v, n, err := vint.Decode(cur)
		if err != nil {
			return 0, false
		}
		cur = cur[n:]
		return v, true
	}
	ver, ok := getV()
	if !ok || ver > 0 {
		return
	}
	flags, ok := getV()
	if !ok {
		return
	}
	if len(cur) < 1+16 {
		return
	}
	ac := &arcCrypt5{lg2Count: cur[0]}
	cur = cur[1:]
	copy(ac.salt[:], cur[:16])
	cur = cur[16:]
	ac.useCheck = flags&1 != 0
	if ac.useCheck {
		if len(cur) < 12 {
			ac.useCheck = false
		} else {
			copy(ac.pswCheck[:], cur[:8])
			h := sha256.Sum256(cur[:8])
			ac.checkOK = string(cur[8:12]) == string(h[:4])
		}
	}
	r.arcCrypt5 = ac
}

// arcKeys5 派生 RAR5 头加密密钥，并做口令预检。
func (r *Reader) arcKeys5(password string) (key, hashKey [32]byte, ivIgnored [16]byte, err error) {
	ac := r.arcCrypt5
	ck := kdfCacheKey("rar5h", password, ac.salt[:], ac.lg2Count)
	e := r.kdfCached(ck, func() kdfEntry {
		k, hk, pv, ok := rarcrypt.KDF5(password, ac.salt[:], ac.lg2Count)
		if !ok {
			return kdfEntry{}
		}
		return kdfEntry{
			key:     append([]byte(nil), k[:]...),
			hashKey: append([]byte(nil), hk[:]...),
			pswVal:  append([]byte(nil), pv[:]...),
		}
	})
	if len(e.key) != 32 {
		return key, hashKey, ivIgnored, fmt.Errorf("%w: RAR5 KDF", ErrUnsupported)
	}
	copy(key[:], e.key)
	copy(hashKey[:], e.hashKey)
	if ac.useCheck && ac.checkOK {
		var pv [32]byte
		copy(pv[:], e.pswVal)
		if rarcrypt.FoldPswCheck(pv) != ac.pswCheck {
			return key, hashKey, ivIgnored, ErrWrongPassword
		}
	}
	return key, hashKey, ivIgnored, nil
}

// readBlock5Encrypted 读头加密块：[16B IV][16 对齐加密头]，每头独立 CBC。
func (r *Reader) readBlock5Encrypted(vol int, pos int64, key [32]byte) (*block5, error) {
	var initV [16]byte
	if err := r.readFull(vol, pos, initV[:]); err != nil {
		return nil, err
	}
	dec, err := rarcrypt.NewDecrypter(key[:], initV[:])
	if err != nil {
		return nil, err
	}
	var first [16]byte
	if err := r.readFull(vol, pos+16, first[:]); err != nil {
		return nil, err
	}
	dec.Decrypt(first[:])
	sizeVal, sizeLen, err := vint.Decode(first[4:])
	if err != nil {
		return nil, fmt.Errorf("rar: bad RAR5 header size: %w", ErrChecksum)
	}
	total := 4 + int64(sizeLen) + int64(sizeVal)
	if sizeVal == 0 || total < 7 || total > maxHeader5 {
		return nil, fmt.Errorf("rar: bad RAR5 block size %d: %w", sizeVal, ErrChecksum)
	}
	raw := make([]byte, total)
	copy(raw, first[:min(int64(16), total)])
	padded := (total + 15) &^ 15
	if rest := padded - 16; rest > 0 {
		buf := make([]byte, rest)
		if err := r.readFull(vol, pos+16+16, buf); err != nil {
			return nil, err
		}
		dec.Decrypt(buf)
		copy(raw[16:], buf)
	}
	return r.parseBlock5(raw, vol, pos+16+padded)
}

// parseFile5 解析 FILE 块。cont 表示后卷续流。
func (r *Reader) parseFile5(vol int, blk *block5, pending *File) (f *File, cont bool, end bool, err error) {
	cur := blk.body
	getV := func() (uint64, error) {
		v, n, err := vint.Decode(cur)
		if err != nil {
			return 0, fmt.Errorf("rar: truncated RAR5 file header: %w", ErrChecksum)
		}
		cur = cur[n:]
		return v, nil
	}
	fileFlags, err := getV()
	if err != nil {
		return nil, false, false, err
	}
	unpSize, err := getV()
	if err != nil {
		return nil, false, false, err
	}
	fileAttr, err := getV()
	if err != nil {
		return nil, false, false, err
	}
	var mtime time.Time
	if fileFlags&fhflUtime != 0 {
		if len(cur) < 4 {
			return nil, false, false, fmt.Errorf("rar: truncated RAR5 time: %w", ErrChecksum)
		}
		mtime = time.Unix(int64(binary.LittleEndian.Uint32(cur[:4])), 0)
		cur = cur[4:]
	}
	var fileCRC uint32
	hasCRC := false
	if fileFlags&fhflCRC32 != 0 {
		if len(cur) < 4 {
			return nil, false, false, fmt.Errorf("rar: truncated RAR5 crc: %w", ErrChecksum)
		}
		fileCRC = binary.LittleEndian.Uint32(cur[:4])
		cur = cur[4:]
		hasCRC = true
	}
	compInfo, err := getV()
	if err != nil {
		return nil, false, false, err
	}
	hostOS, err := getV()
	if err != nil {
		return nil, false, false, err
	}
	nameSize, err := getV()
	if err != nil {
		return nil, false, false, err
	}
	if uint64(len(cur)) < nameSize || nameSize > 1<<20 {
		return nil, false, false, fmt.Errorf("rar: bad RAR5 name size: %w", ErrChecksum)
	}
	name := normalizeName(string(cur[:nameSize]))

	method := int((compInfo >> 7) & 7)
	unpVer := compInfo & 0x3f
	var winSize uint64
	if unpVer == 0 {
		winSize = 0x20000 << ((compInfo >> 10) & 0x0f)
	} else if unpVer == 1 {
		winSize = 0x20000 << ((compInfo >> 10) & 0x1f)
		winSize += winSize / 32 * ((compInfo >> 15) & 0x1f)
	}
	isDir := fileFlags&fhflDirectory != 0
	splitBefore := blk.flags&hflSplitBefore != 0

	crypt, htime, fhash := parseExtra5(blk.extra)
	encrypted := crypt.present
	if htime.ok {
		mtime = htime.mt
	}

	segSize := blk.next - blk.dataOff
	if splitBefore && pending != nil {
		pending.data.segments = append(pending.data.segments, segment{vol: vol, off: blk.dataOff, size: segSize})
		pending.data.continued = true
		// 续头 CRC：末卷为全文 CRC，中续为本卷 pack 段 CRC；后者为准。
		if hasCRC {
			pending.data.crc = fileCRC
			pending.data.hasCRC = true
		}
		return pending, true, !blk.splitAfter, nil
	}

	f = &File{
		Name:         name,
		UnpackedSize: unpSize,
		Modified:     mtime,
		Mode:         mode5(hostOS, fileAttr, isDir),
		IsDir:        isDir,
		Encrypted:    encrypted,
		Solid:        compInfo&fciSolid != 0,
		r:            r,
		data: fileData{
			method:      method,
			unpVer:      int(unpVer),
			packSize:    blk.dataSize,
			unpSize:     unpSize,
			crc:         fileCRC,
			hasCRC:      hasCRC,
			blake2:      fhash,
			encrypted:   encrypted,
			solid:       compInfo&fciSolid != 0,
			splitAfter:  blk.splitAfter,
			winSize:     winSize,
			sizeUnknown: fileFlags&fhflUnpUnknown != 0,
			crypt5:      crypt,
		},
	}
	if segSize > 0 {
		f.data.segments = append(f.data.segments, segment{vol: vol, off: blk.dataOff, size: segSize})
	}
	return f, false, !blk.splitAfter, nil
}

// fileTime5 是 extra HTIME 给出的 mtime。
type fileTime5 struct {
	mt time.Time
	ok bool
}

// crypt5 是 RAR5 文件加密参数（FHEXTRA_CRYPT）。
type crypt5 struct {
	present     bool
	version     uint64
	lg2Count    byte
	salt        [16]byte
	initV       [16]byte
	usePswCheck bool
	useHashKey  bool
	pswCheck    [8]byte
	pswCheckOK  bool // csum 自校验通过
}

// parseExtra5 走查 extra 区，提取加密参数、高精度时间与 HASH。
func parseExtra5(extra []byte) (crypt5, fileTime5, []byte) {
	var crypt crypt5
	var htime fileTime5
	var hash []byte
	for len(extra) >= 2 {
		fieldSize, n1, err := vint.Decode(extra)
		if err != nil || fieldSize == 0 {
			return crypt, htime, hash
		}
		rest := extra[n1:]
		fieldType, n2, err := vint.Decode(rest)
		if err != nil {
			return crypt, htime, hash
		}
		bodyLen := int(fieldSize) - n2
		if bodyLen < 0 || bodyLen > len(rest[n2:]) {
			return crypt, htime, hash
		}
		body := rest[n2 : n2+bodyLen]
		switch fieldType {
		case extraCrypt:
			crypt = parseCrypt5(body)
		case extraHash:
			if len(body) > 1 {
				// 首 vint 为 HASH 类型（0 = BLAKE2sp），余下 32B 为摘要；
				// 未知类型或长度不符则丢弃该记录（仍以 CRC32 为准）。
				if typ, n, err := vint.Decode(body); err == nil && typ == 0 && len(body)-n == blake2sp.Size {
					hash = append([]byte(nil), body[n:]...)
				}
			}
		case extraHTime:
			if mt, ok := parseHTime5(body); ok {
				htime = fileTime5{mt: mt, ok: true}
			}
		}
		extra = rest[n2+bodyLen:]
	}
	return crypt, htime, hash
}

// parseCrypt5 解析 FHEXTRA_CRYPT 记录体。
func parseCrypt5(body []byte) (c crypt5) {
	cur := body
	getV := func() (uint64, bool) {
		v, n, err := vint.Decode(cur)
		if err != nil {
			return 0, false
		}
		cur = cur[n:]
		return v, true
	}
	ver, ok := getV()
	if !ok {
		return c
	}
	c.version = ver
	flags, ok := getV()
	if !ok {
		return c
	}
	if len(cur) < 1 {
		return c
	}
	c.lg2Count = cur[0]
	cur = cur[1:]
	if len(cur) < 32 {
		return c
	}
	copy(c.salt[:], cur[:16])
	copy(c.initV[:], cur[16:32])
	cur = cur[32:]
	c.usePswCheck = flags&1 != 0
	c.useHashKey = flags&2 != 0
	if c.usePswCheck {
		if len(cur) < 12 {
			c.usePswCheck = false
		} else {
			copy(c.pswCheck[:], cur[:8])
			var digest [32]byte
			h := sha256.Sum256(cur[:8])
			copy(digest[:], h[:])
			c.pswCheckOK = string(cur[8:12]) == string(digest[:4])
		}
	}
	c.present = true
	return c
}

// parseHTime5 解 HTIME 记录的 mtime（仅 Unix 时间）。
func parseHTime5(body []byte) (time.Time, bool) {
	flags, n, err := vint.Decode(body)
	if err != nil {
		return time.Time{}, false
	}
	body = body[n:]
	if flags&(htimeUnixTime|htimeMTime) != htimeUnixTime|htimeMTime {
		return time.Time{}, false
	}
	if flags&htimeUnixNS != 0 {
		if len(body) < 8 {
			return time.Time{}, false
		}
		ns := int64(binary.LittleEndian.Uint64(body[:8]))
		return time.Unix(0, ns), true
	}
	if len(body) < 4 {
		return time.Time{}, false
	}
	return time.Unix(int64(binary.LittleEndian.Uint32(body[:4])), 0), true
}

// mode5 由 HOST_OS 与属性推导文件模式。
func mode5(hostOS uint64, attr uint64, isDir bool) fs.FileMode {
	if hostOS == host5Unix {
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
	if isDir {
		return fs.ModeDir | 0o555
	}
	return 0o666
}
