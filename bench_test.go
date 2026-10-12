package rar

import (
	"bytes"
	"hash/crc32"
	"io"
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/ayasechan/unrar/internal/bitio"
	"github.com/ayasechan/unrar/internal/blake2sp"
	"github.com/ayasechan/unrar/internal/huff"
	"github.com/ayasechan/unrar/internal/rarcrypt"
)

// benchSink 吸收基准结果，阻止编译器消除解码调用。
var benchSink uint64

// openBenchArchive 打开归档并统计可解文件与总输出字节。
// 扫描开销不计入计时，b.N 循环内只测解压。
func openBenchArchive(b *testing.B, arc string, opts ...Option) ([]*File, int64) {
	b.Helper()
	r, err := OpenReader(filepath.Join("testdata", arc), opts...)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { r.Close() })
	var files []*File
	var total int64
	for _, f := range r.File {
		if f.IsDir {
			continue
		}
		files = append(files, f)
		total += int64(f.UnpackedSize)
	}
	if len(files) == 0 {
		b.Fatalf("%s: no decodable files", arc)
	}
	return files, total
}

// benchArchive 每轮按序解出归档内全部文件并丢弃。
// 固实归档中后文件 Open 会重解链首前缀，该代价计入本轮耗时，
// 故固实项的 MB/s 为等效值，仅用于优化前后对照。
func benchArchive(b *testing.B, arc string, opts ...Option) {
	b.Helper()
	files, total := openBenchArchive(b, arc, opts...)
	b.SetBytes(total)
	// 预热一次：页缓存、口令 KDF 缓存（Reader 内）均与稳态解压无关，
	// 先跑一遍再计时，使各次迭代可比。
	for _, f := range files {
		rc, err := f.Open()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, rc); err != nil {
			rc.Close()
			b.Fatal(err)
		}
		if err := rc.Close(); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, f := range files {
			rc, err := f.Open()
			if err != nil {
				b.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, rc); err != nil {
				rc.Close()
				b.Fatal(err)
			}
			if err := rc.Close(); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkDecompressStored(b *testing.B)      { benchArchive(b, "t5store.rar") }
func BenchmarkDecompressRAR4M1(b *testing.B)      { benchArchive(b, "t4m1.rar") }
func BenchmarkDecompressRAR4M5(b *testing.B)      { benchArchive(b, "t4m5.rar") }
func BenchmarkDecompressRAR4Dict64K(b *testing.B) { benchArchive(b, "t4d64k.rar") }
func BenchmarkDecompressRAR4Solid(b *testing.B)   { benchArchive(b, "t4m5s.rar") }
func BenchmarkDecompressRAR4PPM(b *testing.B)     { benchArchive(b, "t4ppm.rar") }
func BenchmarkDecompressRAR4EXE(b *testing.B)     { benchArchive(b, "t4fexe.rar") }
func BenchmarkDecompressRAR4Media(b *testing.B)   { benchArchive(b, "t4fmedia.rar") }
func BenchmarkDecompressRAR4Media2(b *testing.B)  { benchArchive(b, "t4fmedia2.rar") }
func BenchmarkDecompressRAR5M1(b *testing.B)      { benchArchive(b, "t5m1.rar") }
func BenchmarkDecompressRAR5M5(b *testing.B)      { benchArchive(b, "t5m5.rar") }
func BenchmarkDecompressRAR5Dict4M(b *testing.B)  { benchArchive(b, "t5d4m.rar") }
func BenchmarkDecompressRAR5Solid(b *testing.B)   { benchArchive(b, "t5m5s.rar") }
func BenchmarkDecompressRAR5Book(b *testing.B)    { benchArchive(b, "t5book.rar") }
func BenchmarkDecompressRAR5EXE(b *testing.B)     { benchArchive(b, "t5fexe.rar") }
func BenchmarkDecompressRAR5Media(b *testing.B)   { benchArchive(b, "t5fmedia.rar") }
func BenchmarkDecompressRAR5Multi(b *testing.B)   { benchArchive(b, "t5mv.part01.rar") }
func BenchmarkDecompressRAR4Multi(b *testing.B)   { benchArchive(b, "t4mv.part01.rar") }

func BenchmarkDecompressRAR4Encrypted(b *testing.B) {
	benchArchive(b, "t4pem.rar", WithPassword("secret"))
}

func BenchmarkDecompressRAR5Encrypted(b *testing.B) {
	benchArchive(b, "t5pem.rar", WithPassword("secret"))
}

// BenchmarkOpenScan 度量归档扫描（含卷打开与头解析），解压不在计时内。
func BenchmarkOpenScan(b *testing.B) {
	for i := 0; i < b.N; i++ {
		r, err := OpenReader(filepath.Join("testdata", "t5book.rar"))
		if err != nil {
			b.Fatal(err)
		}
		r.Close()
	}
}

// benchBitioReader 构造可续流的位流；耗尽时重建，保证 b.N 次解码不断流。
func benchBitioReader(data []byte) *bitio.Reader {
	br := bitio.NewReader(bytes.NewReader(data))
	br.Refill()
	return br
}

func refillBenchBitio(br **bitio.Reader, data []byte) {
	if (*br).InAddr <= (*br).ReadTop-30 {
		return
	}
	*br = benchBitioReader(data)
}

// BenchmarkHuffDecode 度量 Huffman 快慢双路解码（含位流取值）。
func BenchmarkHuffDecode(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	lens := make([]byte, nc30)
	for i := range lens {
		lens[i] = byte(1 + rng.Intn(10))
	}
	tbl := huff.MakeTables(lens, nc30)
	data := make([]byte, 1<<20)
	rng.Read(data)
	br := benchBitioReader(data)
	var acc uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refillBenchBitio(&br, data)
		acc += uint64(tbl.Decode(br))
	}
	benchSink = acc
}

// BenchmarkBitioGetAdd 度量位流预览与消费对。
func BenchmarkBitioGetAdd(b *testing.B) {
	rng := rand.New(rand.NewSource(2))
	data := make([]byte, 1<<20)
	rng.Read(data)
	br := benchBitioReader(data)
	var acc uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refillBenchBitio(&br, data)
		acc += uint64(br.GetBits())
		br.AddBits(5)
	}
	benchSink = acc
}

// BenchmarkBlake2sp 度量 RAR5 文件哈希吞吐。
func BenchmarkBlake2sp(b *testing.B) {
	rng := rand.New(rand.NewSource(3))
	buf := make([]byte, 1<<20)
	rng.Read(buf)
	h := blake2sp.New()
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf)
		sum := h.Sum()
		benchSink += uint64(sum[0])
	}
}

// BenchmarkCRC32 度量校验基线吞吐。
func BenchmarkCRC32(b *testing.B) {
	rng := rand.New(rand.NewSource(4))
	buf := make([]byte, 1<<20)
	rng.Read(buf)
	h := crc32.NewIEEE()
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf)
		benchSink += uint64(h.Sum32())
	}
}

// BenchmarkAESDecrypt 度量加密归档的 CBC 解密吞吐。
func BenchmarkAESDecrypt(b *testing.B) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rng := rand.New(rand.NewSource(5))
	rng.Read(key)
	rng.Read(iv)
	dec, err := rarcrypt.NewDecrypter(key, iv)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 32768)
	rng.Read(buf)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec.Decrypt(buf)
		benchSink += uint64(buf[0])
	}
}

// BenchmarkRAR5DeltaFilter 度量 RAR5 Delta 过滤器。
func BenchmarkRAR5DeltaFilter(b *testing.B) {
	rng := rand.New(rand.NewSource(6))
	data := make([]byte, 1<<16)
	rng.Read(data)
	u := &unpack50{}
	flt := &filter5{typ: filterDelta5, channels: 4}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := u.applyFilter(data, flt)
		benchSink += uint64(out[0] + out[len(out)-1])
	}
}

// BenchmarkRAR5E8Filter 度量 RAR5 E8 过滤器。
func BenchmarkRAR5E8Filter(b *testing.B) {
	rng := rand.New(rand.NewSource(7))
	data := make([]byte, 1<<16)
	rng.Read(data)
	for i := 0; i+5 < len(data); i += 97 {
		data[i] = 0xe8
	}
	u := &unpack50{}
	flt := &filter5{typ: filterE85}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := u.applyFilter(data, flt)
		benchSink += uint64(out[0] + out[len(out)-1])
	}
}
