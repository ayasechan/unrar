// Package rar 提供 RAR4 / RAR5 归档的只读解压。
//
// 只支持解压与列表，不支持创建压缩包。
// API 对齐 archive/zip 的使用习惯：OpenReader / NewReader 拿到 Reader，
// 遍历 File 后调用 File.Open 流式读取。
package rar

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 通用错误，调用方用 errors.Is 判定。
var (
	ErrUnsupported   = errors.New("rar: unsupported feature")
	ErrEncrypted     = errors.New("rar: file is encrypted")
	ErrWrongPassword = errors.New("rar: wrong password")
	ErrMissingVolume = errors.New("rar: missing volume")
	ErrNeedRecovery  = errors.New("rar: recovery needed")
	ErrChecksum      = errors.New("rar: checksum mismatch")
)

// Options 控制 Reader 行为，全部通过 Option 写入。
type Options struct {
	password         []byte
	passwordReader   func(file string) (string, error)
	recovery         bool
	revs             RevSet
	filenameEncoding FilenameEncoding
}

// Option 写入一个配置项。
type Option func(*Options)

// WithPassword 用固定口令解密（RAR4/RAR5 通用）。
func WithPassword(s string) Option {
	return func(o *Options) { o.password = []byte(s) }
}

// WithPasswordReader 按文件回调口令，支持多密码与重试。
func WithPasswordReader(fn func(file string) (string, error)) Option {
	return func(o *Options) { o.passwordReader = fn }
}

// WithRecovery 允许用嵌入式恢复记录或恢复卷自动修复损坏/缺卷。
func WithRecovery(enable bool) Option {
	return func(o *Options) { o.recovery = enable }
}

// FilenameEncoding 指定 RAR4 纯 ANSI 文件名的字符集。
// 仅作用于无 Unicode 扩展的老归档；RAR5（UTF-8）与带扩展名忽略。
type FilenameEncoding string

const (
	EncodingUTF8     FilenameEncoding = "utf-8"
	EncodingGBK      FilenameEncoding = "gbk"
	EncodingBig5     FilenameEncoding = "big5"
	EncodingShiftJIS FilenameEncoding = "shift_jis"
	EncodingEUCKR    FilenameEncoding = "euc-kr"
)

// WithFilenameEncoding 指定 RAR4 纯 ANSI 文件名的解码字符集。
// 缺省（空或 utf-8）保持原字节直透；未知取值同样回落直透。
func WithFilenameEncoding(enc FilenameEncoding) Option {
	return func(o *Options) { o.filenameEncoding = enc }
}

// VolumeSet 抽象多分卷归档的卷集合。
// 默认实现按首卷文件名自动发现兄弟卷；测试与对象存储可注入自定义实现。
type VolumeSet interface {
	// FirstName 返回首卷名。
	FirstName() string
	// List 返回已发现的全部卷名（按序号）。
	List() []string
	// OpenVolume 按卷名打开一个卷，返回 ReaderAt、大小与关闭函数。
	OpenVolume(name string) (io.ReaderAt, int64, func() error, error)
}

// Reader 是已打开的归档，只读。
type Reader struct {
	File     []*File
	Comment  string
	Version  int // 4 或 5
	solidArc bool

	opts Options
	vols []openedVolume

	// volNext[i] 表示第 i 卷 ENDARC 置了下卷位。
	volNext []bool

	kdfMu sync.Mutex
	kdf   map[string]kdfEntry

	arcCrypt5 *arcCrypt5
}

// arcCrypt5 是 RAR5 头加密参数（CRYPT 块）。
type arcCrypt5 struct {
	lg2Count uint8
	salt     [16]byte
	useCheck bool
	pswCheck [8]byte
	checkOK  bool
}

// File 描述归档中的一个文件或目录。
type File struct {
	Name         string
	UnpackedSize uint64
	Modified     time.Time
	Mode         fs.FileMode
	IsDir        bool
	Encrypted    bool
	Solid        bool

	r    *Reader
	data fileData
}

// FileInfo 返回 fs.FileInfo 视图。
func (f *File) FileInfo() fs.FileInfo { return fileInfo{f} }

// SafeName 返回可安全落盘的路径：清理分隔符，拒绝绝对路径与 .. 逃逸。
func (f *File) SafeName() (string, error) {
	name := f.Name
	if name == "" || name == "." || name == "/" {
		return "", fmt.Errorf("%w: empty name", ErrUnsupported)
	}
	// 统一分隔符后逐段检查。
	parts := strings.Split(filepath.ToSlash(name), "/")
	var out []string
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			if len(out) == 0 {
				return "", fmt.Errorf("%w: path escape %q", ErrUnsupported, name)
			}
			out = out[:len(out)-1]
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("%w: empty name", ErrUnsupported)
	}
	if filepath.IsAbs(name) || strings.HasPrefix(filepath.ToSlash(name), "/") {
		return "", fmt.Errorf("%w: absolute path %q", ErrUnsupported, name)
	}
	return filepath.Join(out...), nil
}

// Open 打开文件的数据流：透明处理跨卷拼接、解密、解压与校验。
// 每次调用返回独立流，并发安全；调用方必须 Close。
func (f *File) Open() (io.ReadCloser, error) {
	if f.IsDir {
		return io.NopCloser(emptyReader{}), nil
	}
	if f.data.method != 0 {
		if f.r.Version == 4 && f.data.unpVer == 29 {
			return f.openChain29()
		}
		if f.r.Version == 5 && f.data.unpVer == 0 {
			return f.openChain50()
		}
		return nil, fmt.Errorf("%w: unzip v%d method %d", ErrUnsupported, f.data.unpVer, f.data.method)
	}
	if f.data.splitAfter && !f.data.continued {
		return nil, fmt.Errorf("%w: %s continues in next volume", ErrMissingVolume, f.Name)
	}
	stream, sc, err := f.r.cryptStream(f)
	if err != nil {
		return nil, err
	}
	if !f.data.sizeUnknown {
		stream = io.LimitReader(stream, int64(f.data.unpSize))
	}
	return io.NopCloser(newVerifier(stream, &f.data, sc)), nil
}

// Close 释放 Reader 持有的卷句柄。
func (r *Reader) Close() error {
	var err error
	for _, v := range r.vols {
		if v.close == nil {
			continue
		}
		if cerr := v.close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	// 口令清零。
	clear(r.opts.password)
	r.opts.password = nil
	return err
}

// OpenReader 打开本地单卷或多卷归档的首卷。
func OpenReader(name string, opts ...Option) (*Reader, error) {
	vs, err := openOSSet(name)
	if err != nil {
		return nil, err
	}
	return NewReader(vs, opts...)
}

// NewReader 用自定义卷集合打开归档。
func NewReader(vs VolumeSet, opts ...Option) (*Reader, error) {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	names := vs.List()
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: empty volume set", ErrUnsupported)
	}
	rs := o.revs
	if rs == nil && o.recovery {
		rs = autoRevs(vs)
	}
	rds := make([]openedVolume, 0, len(names))
	var openErr error
	for _, n := range names {
		ra, size, close, err := vs.OpenVolume(n)
		if err != nil {
			if rs == nil {
				for _, v := range rds {
					if v.close != nil {
						v.close()
					}
				}
				return nil, err
			}
			// 有恢复卷时容忍缺卷，后续重建。
			rds = append(rds, openedVolume{name: n})
			if openErr == nil {
				openErr = err
			}
			continue
		}
		rds = append(rds, openedVolume{name: n, ra: ra, size: size, close: close})
	}
	r := &Reader{opts: o, vols: rds}
	if rs != nil {
		if err := r.recover(rs, vs, o.revs != nil); err != nil {
			r.Close()
			return nil, err
		}
	}
	if err := r.scan(); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// autoRevs 为本地卷集自动发现同目录恢复卷。
func autoRevs(vs VolumeSet) RevSet {
	osvs, ok := vs.(*osVolumeSet)
	if !ok || len(osvs.names) == 0 {
		return nil
	}
	return discoverRevs(osvs.names[0])
}
