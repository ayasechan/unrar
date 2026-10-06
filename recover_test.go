package rar

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// copyVols 把分卷集拷到临时目录，可选删卷/坏卷。
func copyVols(t *testing.T, pattern string, drop map[string]bool, corrupt map[string]int) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := filepath.Glob(filepath.Join("testdata", pattern))
	if err != nil || len(entries) == 0 {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	for _, e := range entries {
		base := filepath.Base(e)
		if drop[base] {
			continue
		}
		b, err := os.ReadFile(e)
		if err != nil {
			t.Fatal(err)
		}
		if off, ok := corrupt[base]; ok && off < len(b) {
			b[off] ^= 0xff
		}
		if err := os.WriteFile(filepath.Join(dir, base), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func checkRecoveredFiles(t *testing.T, r *Reader) {
	t.Helper()
	for _, name := range volumeFiles {
		var found *File
		for _, f := range r.File {
			if f.Name == name {
				found = f
			}
		}
		if found == nil {
			t.Fatalf("missing %q", name)
		}
		rc, err := found.Open()
		if err != nil {
			t.Fatalf("Open(%s): %v", name, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("Read(%s): %v", name, err)
		}
		want, err := os.ReadFile(filepath.Join("testdata", "golden2", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s: content mismatch", name)
		}
	}
}

// volBytes 取 Reader 卷字节（验证重建一致性）。
func volBytes(t *testing.T, r *Reader, idx int) []byte {
	t.Helper()
	v := r.vols[idx]
	b := make([]byte, v.size)
	if _, err := readAtFull(v.ra, b, 0); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRecoverRAR5Missing(t *testing.T) {
	dir := copyVols(t, "t5mv.part*.rar", map[string]bool{"t5mv.part03.rar": true}, nil)
	// 顺带拷入 rev。
	rb, err := os.ReadFile(filepath.Join("testdata", "t5mv.part01.rev"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "t5mv.part01.rev"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(filepath.Join(dir, "t5mv.part01.rar"), WithRecovery(true))
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	checkRecoveredFiles(t, r)
	want, _ := os.ReadFile(filepath.Join("testdata", "t5mv.part03.rar"))
	if got := volBytes(t, r, 2); string(got) != string(want) {
		t.Fatal("rebuilt part03 not byte-identical")
	}
}

func TestRecoverRAR5LastShort(t *testing.T) {
	dir := copyVols(t, "t5mv.part*.rar", map[string]bool{"t5mv.part05.rar": true}, nil)
	rb, err := os.ReadFile(filepath.Join("testdata", "t5mv.part01.rev"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "t5mv.part01.rev"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(filepath.Join(dir, "t5mv.part01.rar"), WithRecovery(true))
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	checkRecoveredFiles(t, r)
	want, _ := os.ReadFile(filepath.Join("testdata", "t5mv.part05.rar"))
	if got := volBytes(t, r, 4); string(got) != string(want) {
		t.Fatal("rebuilt part05 not byte-identical")
	}
}

func TestRecoverRAR5Corrupt(t *testing.T) {
	dir := copyVols(t, "t5mv.part*.rar", nil, map[string]int{"t5mv.part02.rar": 1000})
	rb, err := os.ReadFile(filepath.Join("testdata", "t5mv.part01.rev"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "t5mv.part01.rev"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(filepath.Join(dir, "t5mv.part01.rar"), WithRecovery(true))
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	checkRecoveredFiles(t, r)
	want, _ := os.ReadFile(filepath.Join("testdata", "t5mv.part02.rar"))
	if got := volBytes(t, r, 1); string(got) != string(want) {
		t.Fatal("rebuilt part02 not byte-identical")
	}
}

func TestRecoverRAR4New(t *testing.T) {
	dir := copyVols(t, "t4mv.part*.rar", map[string]bool{"t4mv.part03.rar": true}, nil)
	rb, err := os.ReadFile(filepath.Join("testdata", "t4mv.part1.rev"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "t4mv.part1.rev"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(filepath.Join(dir, "t4mv.part01.rar"), WithRecovery(true))
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	checkRecoveredFiles(t, r)
	want, _ := os.ReadFile(filepath.Join("testdata", "t4mv.part03.rar"))
	if got := volBytes(t, r, 2); string(got) != string(want) {
		t.Fatal("rebuilt part03 not byte-identical")
	}
}

func TestRecoverRAR4LastShort(t *testing.T) {
	dir := copyVols(t, "t4mv.part*.rar", map[string]bool{"t4mv.part05.rar": true}, nil)
	rb, err := os.ReadFile(filepath.Join("testdata", "t4mv.part1.rev"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "t4mv.part1.rev"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(filepath.Join(dir, "t4mv.part01.rar"), WithRecovery(true))
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	checkRecoveredFiles(t, r)
	want, _ := os.ReadFile(filepath.Join("testdata", "t4mv.part05.rar"))
	if got := volBytes(t, r, 4); string(got) != string(want) {
		t.Fatal("rebuilt part05 not byte-identical")
	}
}

func TestRecoverRAR4Old(t *testing.T) {
	dir := copyVols(t, "t4mvo.r*", map[string]bool{"t4mvo.r01": true}, nil)
	rb, err := os.ReadFile(filepath.Join("testdata", "t4mvo1.rev"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "t4mvo1.rev"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(filepath.Join(dir, "t4mvo.rar"), WithRecovery(true))
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	checkRecoveredFiles(t, r)
	want, _ := os.ReadFile(filepath.Join("testdata", "t4mvo.r01"))
	if got := volBytes(t, r, 2); string(got) != string(want) {
		t.Fatal("rebuilt r01 not byte-identical")
	}
}

func TestRecoverTooManyMissing(t *testing.T) {
	dir := copyVols(t, "t5mv.part*.rar", map[string]bool{
		"t5mv.part02.rar": true,
		"t5mv.part03.rar": true,
	}, nil)
	rb, err := os.ReadFile(filepath.Join("testdata", "t5mv.part01.rev"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "t5mv.part01.rev"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = OpenReader(filepath.Join(dir, "t5mv.part01.rar"), WithRecovery(true))
	if !errors.Is(err, ErrNeedRecovery) {
		t.Fatalf("err = %v, want ErrNeedRecovery", err)
	}
}

func TestRecoverWithRevsMem(t *testing.T) {
	// 内存卷集 + 内存 rev。
	rev, err := os.ReadFile(filepath.Join("testdata", "t5mv.part01.rev"))
	if err != nil {
		t.Fatal(err)
	}
	vs := MemVolumes{
		Names: []string{"t5mv.part01.rar", "t5mv.part02.rar", "t5mv.part04.rar", "t5mv.part05.rar"},
		Data:  map[string][]byte{},
	}
	for _, n := range vs.Names {
		b, err := os.ReadFile(filepath.Join("testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		vs.Data[n] = b
	}
	rs := MemRevs{Names: []string{"t5mv.part01.rev"}, Data: map[string][]byte{"t5mv.part01.rev": rev}}
	r, err := NewReader(vs, WithRevs(rs))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer r.Close()
	checkRecoveredFiles(t, r)
}
