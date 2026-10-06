package rar

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ayasechan/unrar/internal/rs16"
	"github.com/ayasechan/unrar/internal/rs8"
	"github.com/ayasechan/unrar/internal/volumes"
)

var newStyleVol = regexp.MustCompile(`^(.*)\.part(\d+)\.rar$`)

// RevSet 提供恢复卷。
type RevSet interface {
	// ListRevs 返回已发现的恢复卷名。
	ListRevs() []string
	// OpenRev 打开一个恢复卷。
	OpenRev(name string) (io.ReaderAt, int64, func() error, error)
}

// MemRevs 是基于内存的 RevSet 实现，供测试使用。
type MemRevs struct {
	Names []string
	Data  map[string][]byte
}

func (m MemRevs) ListRevs() []string { return m.Names }

func (m MemRevs) OpenRev(name string) (io.ReaderAt, int64, func() error, error) {
	b, ok := m.Data[name]
	if !ok {
		return nil, 0, nil, fmt.Errorf("%w: %s", ErrMissingVolume, name)
	}
	return &byteReaderAt{b: b}, int64(len(b)), nil, nil
}

// osRevSet 是基于本地文件的 RevSet 实现。
type osRevSet struct {
	dir   string
	names []string
}

func (s *osRevSet) ListRevs() []string { return s.names }

func (s *osRevSet) OpenRev(name string) (io.ReaderAt, int64, func() error, error) {
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

// discoverRevs 在首卷同目录按命名风格发现恢复卷。
func discoverRevs(first string) RevSet {
	abs := first
	if !filepath.IsAbs(abs) {
		var err error
		abs, err = filepath.Abs(first)
		if err != nil {
			return nil
		}
	}
	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	// 卷序号部分剥离，得到归档基名。
	volBase := base
	if m := newStyleVol.FindStringSubmatch(base); m != nil {
		volBase = m[1]
	} else if strings.HasSuffix(base, ".rar") {
		volBase = base[:len(base)-4]
	} else {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".rev") {
			continue
		}
		stem := n[:len(n)-4]
		// 新式：base.partNN / base.partN；旧式：baseNN。
		rest := ""
		if !strings.HasPrefix(stem, volBase) {
			continue
		}
		rest = stem[len(volBase):]
		rest = strings.TrimPrefix(rest, ".")
		// 允许 partNNN 或纯数字。
		rest = strings.TrimPrefix(rest, "part")
		if rest == "" {
			continue
		}
		isNum := true
		for _, c := range rest {
			if c < '0' || c > '9' {
				isNum = false
				break
			}
		}
		if !isNum {
			continue
		}
		names = append(names, filepath.Join(dir, n))
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return &osRevSet{dir: dir, names: names}
}

// trailingDigits 取名尾十进制数（RAR5 卷号用）。
func trailingDigits(name string) (uint, bool) {
	base := filepath.Base(name)
	i := len(base)
	for i > 0 && base[i-1] >= '0' && base[i-1] <= '9' {
		i--
	}
	if i == len(base) {
		return 0, false
	}
	n, err := strconv.Atoi(base[i:])
	if err != nil {
		return 0, false
	}
	return uint(n), true
}

// rev5Sign 是 RAR5 恢复卷签名。
var rev5Sign = []byte{'R', 'a', 'r', '!', 0x1a, 'R', 'e', 'v'}

// rev5 是解析后的 RAR5 恢复卷。
type rev5 struct {
	dataCount uint
	recCount  uint
	recNum    uint
	revCRC    uint32
	sizes     []uint64
	crcs      []uint32
	body      []byte // ECC 数据（头之后）。
}

// parseRev5 解析 RAR5 .rev 文件。ok=false 表无效。
func parseRev5(data []byte) (rev5, bool) {
	var r rev5
	if len(data) < 16 || string(data[:8]) != string(rev5Sign) {
		return r, false
	}
	blockCRC := le32(data[8:])
	headerSize := le32(data[12:])
	if headerSize > 1<<20 || headerSize <= 5 || 16+int(headerSize) > len(data) {
		return r, false
	}
	head := data[16 : 16+headerSize]
	calc := crc32.Checksum(data[12:16], crc32.IEEETable)
	calc = crc32.Update(calc, crc32.IEEETable, head)
	if calc != blockCRC {
		return r, false
	}
	pos := 0
	if head[pos] != 1 {
		return r, false
	}
	pos++
	if len(head) < pos+6 {
		return r, false
	}
	r.dataCount = uint(le16(head[pos:]))
	r.recCount = uint(le16(head[pos+2:]))
	r.recNum = uint(le16(head[pos+4:]))
	pos += 6
	total := r.dataCount + r.recCount
	if r.recNum >= total || total > 65535 || r.dataCount == 0 || r.recCount == 0 {
		return r, false
	}
	if len(head) < pos+4 {
		return r, false
	}
	r.revCRC = le32(head[pos:])
	pos += 4
	r.sizes = make([]uint64, r.dataCount)
	r.crcs = make([]uint32, r.dataCount)
	for i := uint(0); i < r.dataCount; i++ {
		if len(head) < pos+12 {
			return r, false
		}
		r.sizes[i] = le64(head[pos:])
		r.crcs[i] = le32(head[pos+8:])
		pos += 12
	}
	// ECC 数据为头之后全部。
	r.body = data[16+headerSize:]
	// RevCRC 校验 ECC 数据。
	if crc32.Checksum(r.body, crc32.IEEETable) != r.revCRC {
		return r, false
	}
	return r, true
}

func le16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func le64(b []byte) uint64 {
	return uint64(le32(b)) | uint64(le32(b[4:]))<<32
}

// recover5 用 RAR5 恢复卷重建缺失数据卷，返回 卷序号→字节。
func recover5(datas [][]byte, sizes []uint64, crcs []uint32, revs [][]byte) (map[int][]byte, error) {
	dataCount, recCount := len(datas), len(revs)
	valid := make([]bool, dataCount+recCount)
	var missing []int
	for i, d := range datas {
		if d == nil {
			missing = append(missing, i)
			continue
		}
		if crc32.Checksum(d, crc32.IEEETable) != crcs[i] {
			missing = append(missing, i)
			continue
		}
		valid[i] = true
	}
	for j, rb := range revs {
		if rb != nil {
			valid[dataCount+j] = true
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}
	found := 0
	for j := range revs {
		if valid[dataCount+j] {
			found++
		}
	}
	if len(missing) > found {
		return nil, fmt.Errorf("%w: %d missing, %d recovery", ErrNeedRecovery, len(missing), found)
	}
	var rs rs16.Coder
	if !rs.Init(uint(dataCount), uint(recCount), valid) {
		return nil, fmt.Errorf("%w: rs init", ErrNeedRecovery)
	}
	const chunk = 1 << 20
	recBuf := chunk
	if recBuf%2 == 1 {
		recBuf--
	}
	out := make(map[int][]byte, len(missing))
	bufs := make([][]byte, len(missing))
	for i := range bufs {
		bufs[i] = make([]byte, recBuf)
	}
	var maxSize uint64
	for _, s := range sizes {
		if s > maxSize {
			maxSize = s
		}
	}
	outIdx := make(map[int]int, len(missing))
	for k, m := range missing {
		outIdx[m] = k
	}
	var processed uint64
	for {
		units := make([][]byte, dataCount)
		maxRead := 0
		revCursor := 0
		for i := 0; i < dataCount; i++ {
			src := datas[i]
			if !valid[i] {
				for !valid[dataCount+revCursor] {
					revCursor++
				}
				src = revs[revCursor]
				revCursor++
			}
			c := make([]byte, recBuf)
			n := 0
			if uint64(len(src)) > processed {
				n = copy(c, src[processed:])
			}
			units[i] = c
			if n > maxRead {
				maxRead = n
			}
		}
		if maxRead == 0 {
			break
		}
		toProcess := recBuf
		if remain := int64(maxSize) - int64(processed); remain < int64(toProcess) {
			if remain <= 0 {
				break // 数据侧已覆盖完。
			}
			toProcess = int(remain)
		}
		for i := 0; i < dataCount; i++ {
			for e := 0; e < len(missing); e++ {
				rs.UpdateECC(uint(i), uint(e), units[i], bufs[e], toProcess)
			}
		}
		for e, m := range missing {
			remain := int64(sizes[m]) - int64(len(out[m]))
			w := toProcess
			if int64(w) > remain {
				w = int(remain)
			}
			if w > 0 {
				out[m] = append(out[m], bufs[e][:w]...)
			}
		}
		processed += uint64(maxRead)
	}
	return out, nil
}

// rev4 是解析后的 RAR4 恢复卷。
type rev4 struct {
	fileNumber int    // 数据卷数 P[2]。
	recNumber  int    // 恢复卷数 P[1]。
	slot       int    // 本卷槽位 = P[2]+P[0]-1。
	body       []byte // ECC 数据（去尾 7 字节）。
}

// parseRev4 解析 RAR4 .rev 文件（新式，带 7 字节尾）。ok=false 表无效。
func parseRev4(data []byte) (rev4, bool) {
	var r rev4
	if len(data) < 7 {
		return r, false
	}
	tail := data[len(data)-7:]
	p := [3]int{int(tail[2]) + 1, int(tail[1]) + 1, int(tail[0]) + 1}
	// P = [P0=index, P1=recNumber, P2=fileNumber]。
	if p[0] <= 0 || p[1] <= 0 || p[2] <= 0 || p[1]+p[2] > 255 || p[0]+p[2]-1 > 255 {
		return r, false
	}
	var want uint32
	for i := 0; i < 4; i++ {
		want |= uint32(tail[3+i]) << (uint(i) * 8)
	}
	if crc32.Checksum(data[:len(data)-4], crc32.IEEETable) != want {
		return r, false
	}
	r.fileNumber, r.recNumber = p[2], p[1]
	r.slot = p[2] + p[0] - 1
	r.body = data[:len(data)-7]
	return r, true
}

// validateVolume4 校验单卷 RAR4（头链 CRC + ENDARC DATACRC），返回 ENDARC 偏移。
func validateVolume4(data []byte) (int64, bool) {
	r := &Reader{vols: []openedVolume{{ra: &byteReaderAt{b: data}, size: int64(len(data))}}}
	var mark [7]byte
	if err := r.readFull(0, 0, mark[:]); err != nil {
		return 0, false
	}
	for i := range rar4Mark {
		if mark[i] != rar4Mark[i] {
			return 0, false
		}
	}
	pos := int64(len(rar4Mark))
	size := int64(len(data))
	for pos < size {
		blk, err := r.readBlock4(0, pos)
		if err != nil {
			return 0, false
		}
		pos = blk.next
		if blk.typ == head3EndArc {
			endarcOff := pos - int64(blk.headSize)
			// DATACRC 置位时校验归档 CRC。
			if blk.flags&0x0002 != 0 && len(blk.body) >= 4 {
				want := binary.LittleEndian.Uint32(blk.body[:4])
				if crc32.Checksum(data[:endarcOff], crc32.IEEETable) != want {
					return 0, false
				}
			}
			return endarcOff, true
		}
	}
	return 0, false
}

// recover4 用 RAR4 恢复卷重建缺失数据卷，返回 卷序号→字节。
func recover4(datas [][]byte, revs [][]byte) (map[int][]byte, error) {
	fileNumber, totalFiles := len(datas), len(datas)+len(revs)
	var missing []int
	present := make([]bool, totalFiles)
	for i, d := range datas {
		if d == nil {
			missing = append(missing, i)
			continue
		}
		if _, ok := validateVolume4(d); !ok {
			missing = append(missing, i)
			continue
		}
		present[i] = true
	}
	for j, rb := range revs {
		if rb != nil {
			present[fileNumber+j] = true
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}
	found := 0
	for j := range revs {
		if present[fileNumber+j] {
			found++
		}
	}
	if len(missing) > found {
		return nil, fmt.Errorf("%w: %d missing, %d recovery", ErrNeedRecovery, len(missing), found)
	}
	var rs rs8.Coder
	rs.Init(len(revs))
	// 擦除槽位：缺失数据卷 + 缺失恢复卷。
	var eras []int
	for _, m := range missing {
		eras = append(eras, m)
	}
	for j := range revs {
		if !present[fileNumber+j] {
			eras = append(eras, fileNumber+j)
		}
	}
	const total = 1 << 20
	recBuf := total / totalFiles
	if recBuf < 1 {
		recBuf = 1
	}
	out := make(map[int][]byte, len(missing))
	// 每卷读游标。
	offs := make([]int, totalFiles)
	bufs := make([][]byte, totalFiles)
	for i := range bufs {
		bufs[i] = make([]byte, recBuf)
	}
	for {
		maxRead := 0
		for i := 0; i < totalFiles; i++ {
			var src []byte
			if i < fileNumber {
				if present[i] {
					src = datas[i]
				}
			} else if present[i] {
				src = revs[i-fileNumber]
			}
			n := 0
			if src != nil && offs[i] < len(src) {
				n = copy(bufs[i], src[offs[i]:])
				offs[i] += n
			} else {
				for k := range bufs[i] {
					bufs[i][k] = 0
				}
			}
			if n > maxRead {
				maxRead = n
			}
		}
		if maxRead == 0 {
			break
		}
		// 逐字节 RS 解码。
		for p := 0; p < maxRead; p++ {
			var col [256]byte
			for i := 0; i < totalFiles; i++ {
				col[i] = bufs[i][p]
			}
			if !rs.Decode(col[:totalFiles], totalFiles, eras) {
				return nil, fmt.Errorf("%w: rs decode", ErrNeedRecovery)
			}
			for i := 0; i < totalFiles; i++ {
				bufs[i][p] = col[i]
			}
		}
		for _, m := range missing {
			out[m] = append(out[m], bufs[m][:maxRead]...)
		}
	}
	// 新式：重建卷尾 7 字节清零；末卷按 ENDARC 截断。
	for m, b := range out {
		if len(b) >= 7 {
			copy(b[len(b)-7:], []byte{0, 0, 0, 0, 0, 0, 0})
		}
		out[m] = truncateEndarc(b)
		_ = m
	}
	return out, nil
}

// truncateEndarc 若 ENDARC 后全零则截断。
func truncateEndarc(data []byte) []byte {
	r := &Reader{vols: []openedVolume{{ra: &byteReaderAt{b: data}, size: int64(len(data))}}}
	pos := int64(len(rar4Mark))
	size := int64(len(data))
	for pos < size {
		blk, err := r.readBlock4(0, pos)
		if err != nil {
			return data
		}
		pos = blk.next
		if blk.typ == head3EndArc {
			rest := data[pos:]
			for _, c := range rest {
				if c != 0 {
					return data
				}
			}
			return data[:pos]
		}
	}
	return data
}

// volNumberOf 解析卷名的绝对序号（1 起），old-style .rar=1、.rNN=N+2。
func volNumberOf(first, name string) (int, bool) {
	base := filepath.Base(first)
	n := filepath.Base(name)
	if m := newStyleVol.FindStringSubmatch(base); m != nil {
		m2 := newStyleVol.FindStringSubmatch(n)
		if m2 == nil || m2[1] != m[1] || len(m2[2]) != len(m[2]) {
			return 0, false
		}
		v, err := strconv.Atoi(m2[2])
		if err != nil || v < 1 {
			return 0, false
		}
		return v, true
	}
	if strings.HasSuffix(base, ".rar") {
		b := base[:len(base)-4]
		if n == base {
			return 1, true
		}
		if strings.HasPrefix(n, b+".r") && len(n) == len(b)+5 {
			v, err := strconv.Atoi(n[len(b)+2:])
			if err != nil {
				return 0, false
			}
			return v + 2, true
		}
	}
	return 0, false
}

// siblingName 由首卷名推导第 n 卷（1 起）的完整路径。
func siblingName(first string, n int) (string, bool) {
	dir := filepath.Dir(first)
	sib, err := volumes.Sibling(filepath.Base(first), n)
	if err != nil {
		return "", false
	}
	if dir == "" || dir == "." {
		return sib, true
	}
	return filepath.Join(dir, sib), true
}

// recoveredVol 是装配后的卷（现存或重建）。
type recoveredVol struct {
	name string
	data []byte // 现存卷为 nil（沿用原句柄），重建卷为字节。
	size int64
}

// WithRevs 提供恢复卷（缺卷/坏卷时内存重建）。
func WithRevs(rs RevSet) Option {
	return func(o *Options) { o.revs = rs }
}

// recover 在 revs 存在时评估并重建缺失/损坏卷（原地替换 r.vols）。
// 无可用恢复卷时静默返回（无恢复动作）；显式传入却不可用则报错。
func (r *Reader) recover(rs RevSet, vs VolumeSet, explicit bool) error {
	revNames := rs.ListRevs()
	type rawRev struct {
		name string
		data []byte
	}
	var raws []rawRev
	for _, n := range revNames {
		ra, size, close, err := rs.OpenRev(n)
		if err != nil {
			continue
		}
		b := make([]byte, size)
		_, rerr := readAtFull(ra, b, 0)
		if close != nil {
			close()
		}
		if rerr != nil {
			continue
		}
		raws = append(raws, rawRev{name: n, data: b})
	}
	// RAR5 优先按签名识别。
	var r5 []rev5
	var r4 []rev4
	for _, rw := range raws {
		if rv, ok := parseRev5(rw.data); ok {
			r5 = append(r5, rv)
			_ = rw
		} else if rv4, ok := parseRev4(rw.data); ok {
			r4 = append(r4, rv4)
		}
	}
	if len(r5) > 0 {
		return r.recover5(rs, vs, r5)
	}
	if len(r4) > 0 {
		return r.recover4(rs, vs, r4)
	}
	// 无可用恢复卷：显式传入报需恢复，自动发现则静默跳过。
	if !explicit {
		return nil
	}
	return fmt.Errorf("%w: no usable recovery volumes", ErrNeedRecovery)
}

func readAtFull(ra io.ReaderAt, p []byte, off int64) (int, error) {
	n := 0
	for n < len(p) {
		m, err := ra.ReadAt(p[n:], off+int64(n))
		n += m
		if err != nil {
			if n == len(p) {
				return n, nil
			}
			return n, err
		}
		if m == 0 {
			return n, io.ErrUnexpectedEOF
		}
	}
	return n, nil
}

// recover5 装配 RAR5 恢复（rev 头已解析）。
func (r *Reader) recover5(rs RevSet, vs VolumeSet, revs []rev5) error {
	first := revs[0]
	dataCount, recCount := int(first.dataCount), int(first.recCount)
	// 槽位与 rev 头一致性校验。
	slots := make(map[uint]rev5, len(revs))
	for _, rv := range revs {
		if rv.dataCount != first.dataCount || rv.recCount != first.recCount {
			return fmt.Errorf("%w: mismatched recovery volumes", ErrNeedRecovery)
		}
		if _, dup := slots[rv.recNum]; dup {
			continue
		}
		slots[rv.recNum] = rv
	}
	// 数据卷名扩展到 DataCount。
	names := make([]string, 0, dataCount)
	seen := map[string]bool{}
	for _, v := range r.vols {
		if v.name != "" && !seen[v.name] {
			seen[v.name] = true
			names = append(names, v.name)
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("%w: no volumes", ErrMissingVolume)
	}
	base0 := names[0]
	bySlot := make([]*openedVolume, dataCount)
	for _, v := range r.vols {
		if v.name == "" || v.ra == nil {
			continue
		}
		if n, ok := trailingDigits(v.name); ok && n >= 1 && n <= uint(dataCount) {
			vv := v
			bySlot[n-1] = &vv
		}
	}
	// 缺槽按 Sibling 生成名并尝试打开（容忍缺失）。
	for s := 0; s < dataCount; s++ {
		if bySlot[s] != nil {
			continue
		}
		if vs == nil {
			continue
		}
		nm, ok := siblingName(base0, s+1)
		if !ok {
			continue
		}
		if ra, size, close, err := vs.OpenVolume(nm); err == nil {
			bySlot[s] = &openedVolume{name: nm, ra: ra, size: size, close: close}
		}
	}
	// 读现存卷字节并校验 CRC。
	datas := make([][]byte, dataCount)
	sizes := make([]uint64, dataCount)
	for s := 0; s < dataCount; s++ {
		sizes[s] = first.sizes[s]
		if bySlot[s] == nil {
			continue
		}
		b := make([]byte, bySlot[s].size)
		if _, err := readAtFull(bySlot[s].ra, b, 0); err != nil {
			bySlot[s] = nil
			continue
		}
		datas[s] = b
	}
	// rev 槽位数据。
	revBodies := make([][]byte, recCount)
	for recNum, rv := range slots {
		s := int(recNum) - dataCount
		if s < 0 || s >= recCount {
			continue
		}
		revBodies[s] = rv.body
	}
	rebuilt, err := recover5(datas, sizes, first.crcs, revBodies)
	if err != nil {
		return err
	}
	// 装配最终卷集。
	final := make([]openedVolume, 0, dataCount)
	for s := 0; s < dataCount; s++ {
		if b, ok := rebuilt[s]; ok {
			final = append(final, openedVolume{name: volNameFor(base0, s), ra: &byteReaderAt{b: b}, size: int64(len(b))})
			continue
		}
		if bySlot[s] == nil {
			return fmt.Errorf("%w: volume %d", ErrMissingVolume, s+1)
		}
		final = append(final, *bySlot[s])
	}
	r.vols = final
	return nil
}

// volNameFor 由首卷名推导第 s 卷（0 起）名。
func volNameFor(first string, s int) string {
	if nm, ok := siblingName(first, s+1); ok {
		return nm
	}
	return first
}

// recover4 装配 RAR4 恢复（rev 尾已解析）。
func (r *Reader) recover4(rs RevSet, vs VolumeSet, revs []rev4) error {
	first := revs[0]
	fileNumber, recNumber := first.fileNumber, first.recNumber
	slots := make(map[int][]byte, len(revs))
	for _, rv := range revs {
		if rv.fileNumber != fileNumber || rv.recNumber != recNumber {
			return fmt.Errorf("%w: mismatched recovery volumes", ErrNeedRecovery)
		}
		if _, dup := slots[rv.slot]; dup {
			continue
		}
		slots[rv.slot] = rv.body
	}
	// 数据卷名：现存顺序 + Sibling 扩展。
	var names []string
	seen := map[string]bool{}
	for _, v := range r.vols {
		if v.name != "" && !seen[v.name] {
			seen[v.name] = true
			names = append(names, v.name)
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("%w: no volumes", ErrMissingVolume)
	}
	base0 := names[0]
	bySlot := make([]*openedVolume, fileNumber)
	for i, v := range r.vols {
		if i < fileNumber && v.name != "" && v.ra != nil {
			vv := v
			// RAR4 按枚举顺序占槽（首卷为 0）。
			for s := 0; s < fileNumber; s++ {
				if bySlot[s] == nil {
					bySlot[s] = &vv
					break
				}
			}
		}
	}
	_ = vs
	for s := 0; s < fileNumber; s++ {
		if bySlot[s] != nil {
			continue
		}
		if vs == nil {
			continue
		}
		nm, ok := siblingName(base0, s+1)
		if !ok {
			continue
		}
		if ra, size, close, err := vs.OpenVolume(nm); err == nil {
			bySlot[s] = &openedVolume{name: nm, ra: ra, size: size, close: close}
		}
	}
	// 读现存卷字节并结构校验。
	datas := make([][]byte, fileNumber)
	for s := 0; s < fileNumber; s++ {
		if bySlot[s] == nil {
			continue
		}
		b := make([]byte, bySlot[s].size)
		if _, err := readAtFull(bySlot[s].ra, b, 0); err != nil {
			bySlot[s] = nil
			continue
		}
		if _, ok := validateVolume4(b); !ok {
			bySlot[s] = nil
			continue
		}
		datas[s] = b
	}
	revBodies := make([][]byte, recNumber)
	for slot, body := range slots {
		if slot < fileNumber || slot >= fileNumber+recNumber {
			continue
		}
		revBodies[slot-fileNumber] = body
	}
	rebuilt, err := recover4(datas, revBodies)
	if err != nil {
		return err
	}
	final := make([]openedVolume, 0, fileNumber)
	for s := 0; s < fileNumber; s++ {
		if b, ok := rebuilt[s]; ok {
			final = append(final, openedVolume{name: volNameFor(base0, s), ra: &byteReaderAt{b: b}, size: int64(len(b))})
			continue
		}
		if bySlot[s] == nil {
			return fmt.Errorf("%w: volume %d", ErrMissingVolume, s+1)
		}
		final = append(final, *bySlot[s])
	}
	r.vols = final
	return nil
}
