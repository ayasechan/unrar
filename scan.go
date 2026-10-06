package rar

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ayasechan/unrar/internal/volumes"
)

// openedVolume 是一个已打开的卷。
type openedVolume struct {
	name  string
	ra    io.ReaderAt
	size  int64
	close func() error
}

// dataReader 把文件的分段拼成连续字节流。
func (r *Reader) dataReader(fd *fileData) io.Reader {
	if len(fd.segments) == 1 {
		s := fd.segments[0]
		v := r.vols[s.vol]
		return io.NewSectionReader(v.ra, s.off, s.size)
	}
	parts := make([]io.Reader, 0, len(fd.segments))
	for _, s := range fd.segments {
		v := r.vols[s.vol]
		parts = append(parts, io.NewSectionReader(v.ra, s.off, s.size))
	}
	if len(parts) == 0 {
		return emptyReader{}
	}
	return io.MultiReader(parts...)
}

// segment 是文件压缩流落在某个卷上的一段。
type segment struct {
	vol  int
	off  int64
	size int64
}

// fileData 是扫描阶段记录的单个文件数据描述。
type fileData struct {
	method      int
	unpVer      int
	packSize    uint64
	unpSize     uint64
	crc         uint32
	hasCRC      bool
	blake2      []byte // RAR5 可选 BLAKE2s-256（加密阶段用于校验）。
	encrypted   bool
	solid       bool
	splitAfter  bool
	continued   bool // splitAfter 且后续卷分段已拼接
	winSize     uint64
	sizeUnknown bool
	salt        []byte
	crypt5      crypt5
	segments    []segment
}

// scan 按签名分派到对应版本扫描器。
func (r *Reader) scan() error {
	var mark [8]byte
	if err := r.readFull(0, 0, mark[:]); err != nil {
		return err
	}
	if bytes.Equal(mark[:8], rar5Mark) {
		return r.scan5()
	}
	if bytes.Equal(mark[:7], rar4Mark) {
		return r.scan4()
	}
	return fmt.Errorf("rar: unknown archive signature: %w", ErrUnsupported)
}

// readFull 从指定卷的偏移读满 p。
func (r *Reader) readFull(vol int, off int64, p []byte) error {
	if vol < 0 || vol >= len(r.vols) {
		return fmt.Errorf("%w: volume index %d", ErrMissingVolume, vol)
	}
	sr := io.NewSectionReader(r.vols[vol].ra, off, int64(len(p)))
	_, err := io.ReadFull(sr, p)
	return err
}

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

// osVolumeSet 是基于本地文件的 VolumeSet 实现。
type osVolumeSet struct {
	names []string
	dir   string
}

func openOSSet(first string) (*osVolumeSet, error) {
	abs := first
	if !filepath.IsAbs(abs) {
		var err error
		abs, err = filepath.Abs(first)
		if err != nil {
			return nil, err
		}
	}
	base := filepath.Base(abs)
	dir := filepath.Dir(abs)
	names := []string{abs}
	switch volumes.Detect(base) {
	case volumes.StyleNew:
		for n := 2; ; n++ {
			sib, err := volumes.Sibling(base, n)
			if err != nil {
				break
			}
			p := filepath.Join(dir, sib)
			if _, err := os.Stat(p); err != nil {
				break
			}
			names = append(names, p)
			if len(names) > 1<<20 {
				break
			}
		}
	case volumes.StyleOld:
		for n := 2; ; n++ {
			sib, err := volumes.Sibling(base, n)
			if err != nil {
				break
			}
			p := filepath.Join(dir, sib)
			if _, err := os.Stat(p); err != nil {
				break
			}
			names = append(names, p)
			if len(names) > 1<<20 {
				break
			}
		}
	}
	return &osVolumeSet{names: names, dir: dir}, nil
}

func (s *osVolumeSet) FirstName() string { return s.names[0] }
func (s *osVolumeSet) List() []string    { return s.names }

func (s *osVolumeSet) OpenVolume(name string) (io.ReaderAt, int64, func() error, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, 0, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, nil, err
	}
	return f, st.Size(), f.Close, nil
}

// MemVolumes 是基于内存的 VolumeSet 实现，供测试使用。
type MemVolumes struct {
	Names []string
	Data  map[string][]byte
}

func (m MemVolumes) FirstName() string { return m.Names[0] }
func (m MemVolumes) List() []string    { return m.Names }

func (m MemVolumes) OpenVolume(name string) (io.ReaderAt, int64, func() error, error) {
	b, ok := m.Data[name]
	if !ok {
		return nil, 0, nil, fmt.Errorf("%w: %s", ErrMissingVolume, name)
	}
	return &byteReaderAt{b: b}, int64(len(b)), nil, nil
}

type byteReaderAt struct{ b []byte }

func (r *byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.b)) {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// dosTimeToTime 解 DOS 时间戳（本地墙钟）。
func dosTimeToTime(dos uint32) time.Time {
	sec := int(dos&0x1f) * 2
	min := int((dos >> 5) & 0x3f)
	hr := int((dos >> 11) & 0x1f)
	day := int((dos >> 16) & 0x1f)
	mon := time.Month((dos >> 21) & 0x0f)
	year := int((dos>>25)&0x7f) + 1980
	if mon < 1 || mon > 12 || day < 1 || day > 31 || hr > 23 || min > 59 || sec > 60 {
		return time.Time{}
	}
	return time.Date(year, mon, day, hr, min, sec, 0, time.Local)
}

// checkVolumes 校验分卷链完整性：末卷若置下卷位则报缺卷。
func (r *Reader) checkVolumes() error {
	if len(r.volNext) == 0 {
		return nil
	}
	if r.volNext[len(r.volNext)-1] {
		base := filepath.Base(r.vols[0].name)
		dir := filepath.Dir(r.vols[0].name)
		next, err := volumes.Sibling(base, len(r.vols)+1)
		if err != nil {
			return fmt.Errorf("%w: volume %d", ErrMissingVolume, len(r.vols)+1)
		}
		missing := next
		if !filepath.IsAbs(next) {
			missing = filepath.Join(dir, next)
		}
		return fmt.Errorf("%w: %s", ErrMissingVolume, missing)
	}
	return nil
}

// decodeUnicodeName 解 RAR4 的 LHD_UNICODE 组合名：ANSI + NUL + 编码尾。
func decodeUnicodeName(raw []byte) string {
	nul := -1
	for i, c := range raw {
		if c == 0 {
			nul = i
			break
		}
	}
	if nul < 0 {
		return string(raw)
	}
	ansi := raw[:nul]
	enc := raw[nul+1:]
	if len(enc) == 0 {
		return string(ansi)
	}
	high := enc[0]
	pos := 1
	var out []rune
	flags, bits := 0, 0
	for pos < len(enc) {
		if bits == 0 {
			flags = int(enc[pos])
			pos++
			bits = 8
		}
		switch flags >> 6 {
		case 0:
			if pos >= len(enc) {
				break
			}
			out = append(out, rune(enc[pos]))
			pos++
		case 1:
			if pos >= len(enc) {
				break
			}
			out = append(out, rune(enc[pos])|rune(high)<<8)
			pos++
		case 2:
			if pos+1 >= len(enc) {
				break
			}
			out = append(out, rune(enc[pos])|rune(enc[pos+1])<<8)
			pos += 2
		case 3:
			if pos >= len(enc) {
				break
			}
			length := int(enc[pos])
			pos++
			if length&0x80 != 0 {
				if pos >= len(enc) {
					break
				}
				corr := enc[pos]
				pos++
				for n := (length & 0x7f) + 2; n > 0; n-- {
					if len(out) >= len(ansi) {
						break
					}
					//nolint:gosec // 解码字节运算，结果截断到低 8 位是格式定义行为。
					out = append(out, rune(ansi[len(out)]+corr)|rune(high)<<8)
				}
			} else {
				for n := length + 2; n > 0; n-- {
					if len(out) >= len(ansi) {
						break
					}
					out = append(out, rune(ansi[len(out)]))
				}
			}
		}
		flags = (flags << 2) & 0xff
		bits -= 2
	}
	if len(out) == 0 {
		return string(ansi)
	}
	return string(out)
}
