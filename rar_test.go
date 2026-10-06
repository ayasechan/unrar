package rar

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

var storedFiles = map[string]int64{
	"中文名.txt":        25,
	"empty.txt":      0,
	"data.bin":       4096,
	"hello.txt":      32,
	"sub/nested.txt": 15,
}

var storedDirs = map[string]bool{
	"emptydir": true,
	"sub":      true,
}

func openTestdata(t *testing.T, name string, opts ...Option) *Reader {
	t.Helper()
	r, err := OpenReader(filepath.Join("testdata", name), opts...)
	if err != nil {
		t.Fatalf("OpenReader(%s): %v", name, err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func checkStored(t *testing.T, r *Reader, version int) {
	t.Helper()
	if r.Version != version {
		t.Fatalf("version = %d, want %d", r.Version, version)
	}
	byName := map[string]*File{}
	for _, f := range r.File {
		byName[f.Name] = f
	}
	for name, size := range storedFiles {
		f, ok := byName[name]
		if !ok {
			t.Fatalf("missing file %q (have %v)", name, names(r))
		}
		if f.IsDir {
			t.Fatalf("%q is dir, want file", name)
		}
		if int64(f.UnpackedSize) != size {
			t.Fatalf("%q size = %d, want %d", name, f.UnpackedSize, size)
		}
		if f.Encrypted {
			t.Fatalf("%q marked encrypted", name)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("Open(%q): %v", name, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("Read(%q): %v", name, err)
		}
		want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("golden %q: %v", name, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%q content mismatch (%d vs %d bytes)", name, len(got), len(want))
		}
		if f.Modified.IsZero() && f.UnpackedSize > 0 {
			t.Fatalf("%q has zero mtime", name)
		}
	}
	for name := range storedDirs {
		f, ok := byName[name]
		if !ok {
			t.Fatalf("missing dir %q", name)
		}
		if !f.IsDir {
			t.Fatalf("%q not marked dir", name)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("Open(dir %q): %v", name, err)
		}
		n, _ := rc.Read(make([]byte, 1))
		rc.Close()
		if n != 0 {
			t.Fatalf("dir %q returned data", name)
		}
	}
	if len(byName) != len(storedFiles)+len(storedDirs) {
		t.Fatalf("file count = %d, want %d (%v)", len(byName), len(storedFiles)+len(storedDirs), names(r))
	}
}

func names(r *Reader) []string {
	var out []string
	for _, f := range r.File {
		out = append(out, f.Name)
	}
	return out
}

func TestStoredRAR4(t *testing.T) {
	checkStored(t, openTestdata(t, "t4store.rar"), 4)
}

func TestStoredRAR5(t *testing.T) {
	checkStored(t, openTestdata(t, "t5store.rar"), 5)
}

func TestEncryptedDataListed(t *testing.T) {
	for _, tc := range []struct {
		arc     string
		version int
	}{
		{"t4p.rar", 4},
		{"t5p.rar", 5},
	} {
		r := openTestdata(t, tc.arc)
		if r.Version != tc.version {
			t.Fatalf("%s version = %d", tc.arc, r.Version)
		}
		nEnc := 0
		for _, f := range r.File {
			if f.IsDir {
				continue
			}
			if !f.Encrypted {
				t.Fatalf("%s: %q not marked encrypted", tc.arc, f.Name)
			}
			nEnc++
			if _, err := f.Open(); !errors.Is(err, ErrEncrypted) {
				t.Fatalf("%s: Open(%q) = %v, want ErrEncrypted", tc.arc, f.Name, err)
			}
		}
		if nEnc != len(storedFiles) {
			t.Fatalf("%s: encrypted files = %d, want %d", tc.arc, nEnc, len(storedFiles))
		}
	}
}

func TestDecryptWithPassword(t *testing.T) {
	for _, tc := range []struct {
		arc     string
		version int
	}{
		{"t4p.rar", 4},
		{"t4hp.rar", 4},
		{"t5p.rar", 5},
		{"t5hp.rar", 5},
	} {
		r := openTestdata(t, tc.arc, WithPassword("secret"))
		if r.Version != tc.version {
			t.Fatalf("%s version = %d", tc.arc, r.Version)
		}
		for name, size := range storedFiles {
			var found *File
			for _, f := range r.File {
				if f.Name == name {
					found = f
				}
			}
			if found == nil {
				t.Fatalf("%s: missing %q", tc.arc, name)
			}
			if int64(found.UnpackedSize) != size {
				t.Fatalf("%s %q size = %d", tc.arc, name, found.UnpackedSize)
			}
			rc, err := found.Open()
			if err != nil {
				t.Fatalf("%s Open(%s): %v", tc.arc, name, err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("%s Read(%s): %v", tc.arc, name, err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.FromSlash(name)))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("%s %s: content mismatch", tc.arc, name)
			}
		}
	}
}

func TestCompressedEncrypted(t *testing.T) {
	for _, tc := range []struct {
		arc   string
		files []string
	}{
		{"t4pem.rar", compressedFiles},
		{"t5pem.rar", compressed5Files},
	} {
		r, err := OpenReader(filepath.Join("testdata", tc.arc), WithPassword("secret"))
		if err != nil {
			t.Fatalf("OpenReader(%s): %v", tc.arc, err)
		}
		defer r.Close()
		for _, name := range tc.files {
			var found *File
			for _, f := range r.File {
				if f.Name == name {
					found = f
				}
			}
			if found == nil {
				t.Fatalf("%s: missing %q", tc.arc, name)
			}
			rc, err := found.Open()
			if err != nil {
				t.Fatalf("%s Open(%s): %v", tc.arc, name, err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("%s Read(%s): %v", tc.arc, name, err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", "golden2", filepath.FromSlash(name)))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("%s %s: content mismatch", tc.arc, name)
			}
		}
	}
}

func TestPasswordReader(t *testing.T) {
	calls := 0
	r, err := OpenReader(filepath.Join("testdata", "t5p.rar"), WithPasswordReader(func(file string) (string, error) {
		calls++
		if file == "" {
			return "", io.ErrUnexpectedEOF
		}
		return "secret", nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, f := range r.File {
		if f.IsDir {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("Read(%s): %v", f.Name, err)
		}
	}
	if calls == 0 {
		t.Fatal("callback never invoked")
	}
}

func TestWrongPassword(t *testing.T) {
	for _, arc := range []string{"t4p.rar", "t5p.rar"} {
		r := openTestdata(t, arc, WithPassword("wrong"))
		var target *File
		for _, f := range r.File {
			if !f.IsDir && f.UnpackedSize > 0 {
				target = f
				break
			}
		}
		if target == nil {
			t.Fatalf("%s: no target", arc)
		}
		rc, err := target.Open()
		if err != nil {
			if !errors.Is(err, ErrWrongPassword) {
				t.Fatalf("%s Open: %v", arc, err)
			}
			continue
		}
		_, err = io.ReadAll(rc)
		rc.Close()
		if !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("%s Read: %v, want ErrWrongPassword", arc, err)
		}
	}
}

func TestEncryptedHeaders(t *testing.T) {
	_, err := OpenReader(filepath.Join("testdata", "t5hp.rar"))
	if !errors.Is(err, ErrEncrypted) {
		t.Fatalf("OpenReader(t5hp.rar) = %v, want ErrEncrypted", err)
	}
	_, err = OpenReader(filepath.Join("testdata", "t4hp.rar"))
	if !errors.Is(err, ErrEncrypted) {
		t.Fatalf("OpenReader(t4hp.rar) = %v, want ErrEncrypted", err)
	}
	// 错口令头解密失败。
	_, err = OpenReader(filepath.Join("testdata", "t5hp.rar"), WithPassword("wrong"))
	if !errors.Is(err, ErrWrongPassword) && !errors.Is(err, ErrEncrypted) {
		t.Fatalf("OpenReader(t5hp.rar, wrong) = %v", err)
	}
	_, err = OpenReader(filepath.Join("testdata", "t4hp.rar"), WithPassword("wrong"))
	if !errors.Is(err, ErrWrongPassword) && !errors.Is(err, ErrEncrypted) {
		t.Fatalf("OpenReader(t4hp.rar, wrong) = %v", err)
	}
}

func TestCorruptDataDetected(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "t4store.rar"))
	if err != nil {
		t.Fatal(err)
	}
	// 先正常打开，找到第一个文件的数据段再破坏它。
	r1, err := NewReader(MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": raw}})
	if err != nil {
		t.Fatal(err)
	}
	var seg segment
	for _, f := range r1.File {
		if !f.IsDir && len(f.data.segments) > 0 {
			seg = f.data.segments[0]
			break
		}
	}
	r1.Close()
	if seg.size == 0 {
		t.Fatal("no data segment found")
	}
	bad := append([]byte(nil), raw...)
	bad[seg.off] ^= 0xff
	r2, err := NewReader(MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": bad}})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	var target *File
	for _, f := range r2.File {
		if !f.IsDir && len(f.data.segments) > 0 && f.data.segments[0].off == seg.off {
			target = f
		}
	}
	if target == nil {
		t.Fatal("target file missing after corruption")
	}
	rc, err := target.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.ReadAll(rc); !errors.Is(err, ErrChecksum) {
		t.Fatalf("Read = %v, want ErrChecksum", err)
	}
}

func TestTruncatedAndGarbage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "t4store.rar"))
	if err != nil {
		t.Fatal(err)
	}
	mem := func(b []byte) VolumeSet {
		return MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": b}}
	}
	if _, err := NewReader(mem(raw[:len(raw)/2])); err == nil {
		t.Fatal("truncated archive: want error")
	}
	if _, err := NewReader(mem([]byte("not a rar file at all........"))); err == nil {
		t.Fatal("garbage: want error")
	}
	if _, err := OpenReader(filepath.Join("testdata", "no-such.rar")); err == nil {
		t.Fatal("missing file: want error")
	}
}
