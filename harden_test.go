package rar

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSafeName(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"hello.txt", true},
		{"sub/nested.txt", true},
		{`sub\nested.txt`, true},
		{"../evil.txt", false},
		{"sub/../../evil.txt", false},
		{"/abs/path.txt", false},
		{"", false},
		{".", false},
		{"sub/./ok.txt", true},
	} {
		f := &File{Name: tc.in}
		got, err := f.SafeName()
		if tc.ok && err != nil {
			t.Fatalf("SafeName(%q) = %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("SafeName(%q) = %q, want error", tc.in, got)
		}
		if tc.ok && got == "" {
			t.Fatalf("SafeName(%q) empty", tc.in)
		}
	}
}

// TestCorruptNeverPanics 随机破坏夹具：只允许报错，不允许 panic。
func TestCorruptNeverPanics(t *testing.T) {
	seeds := []string{
		"t4store.rar", "t5store.rar", "t4m5.rar", "t5m5.rar",
		"t4m5s.rar", "t5m5s.rar", "t4ppm.rar", "t4fexe.rar",
		"t4cmt.rar", "t5cmt.rar",
	}
	xor := uint32(0x9e3779b9)
	next := func() uint32 {
		xor ^= xor << 13
		xor ^= xor >> 17
		xor ^= xor << 5
		return xor
	}
	for _, s := range seeds {
		raw := readTestdata(t, s)
		n := 30
		if len(raw) > 500000 {
			n = 5
		}
		for i := 0; i < n; i++ {
			bad := append([]byte(nil), raw...)
			for k := 0; k < 1+int(next()%4); k++ {
				bad[next()%uint32(len(bad))] ^= byte(next())
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s flip %d: panic %v", s, i, r)
					}
				}()
				r, err := NewReader(MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": bad}})
				if err != nil {
					return
				}
				defer r.Close()
				for _, f := range r.File {
					if f.IsDir {
						continue
					}
					rc, err := f.Open()
					if err != nil {
						continue
					}
					_, _ = io.Copy(io.Discard, rc)
					rc.Close()
				}
			}()
		}
	}
}

func BenchmarkStored(b *testing.B) {
	r, err := OpenReader(filepath.Join("testdata", "t5store.rar"))
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	var f *File
	for _, x := range r.File {
		if x.Name == "data.bin" {
			f = x
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc, _ := f.Open()
		io.Copy(io.Discard, rc)
		rc.Close()
	}
}

func BenchmarkUnpack29(b *testing.B) {
	r, err := OpenReader(filepath.Join("testdata", "t4m5.rar"))
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	var f *File
	for _, x := range r.File {
		if x.Name == "text.txt" {
			f = x
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc, _ := f.Open()
		io.Copy(io.Discard, rc)
		rc.Close()
	}
}

func BenchmarkUnpack50(b *testing.B) {
	r, err := OpenReader(filepath.Join("testdata", "t5book.rar"))
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc, _ := r.File[0].Open()
		io.Copy(io.Discard, rc)
		rc.Close()
	}
}
