package rar

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

var volumeFiles = []string{"exeish.bin", "text.txt", "sub/n2.txt"}

func checkVolumes(t *testing.T, first string, opts ...Option) {
	t.Helper()
	r, err := OpenReader(filepath.Join("testdata", first), opts...)
	if err != nil {
		t.Fatalf("OpenReader(%s): %v", first, err)
	}
	defer r.Close()
	if len(r.vols) < 2 {
		t.Fatalf("%s: vols = %d, want multi", first, len(r.vols))
	}
	for _, name := range volumeFiles {
		var found *File
		for _, f := range r.File {
			if f.Name == name {
				found = f
			}
		}
		if found == nil {
			t.Fatalf("%s: missing %q", first, name)
		}
		if len(found.data.segments) < 2 {
			t.Logf("%s %s: single-segment (%d segs)", first, name, len(found.data.segments))
		}
		rc, err := found.Open()
		if err != nil {
			t.Fatalf("%s Open(%s): %v", first, name, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s Read(%s): %v", first, name, err)
		}
		want, err := os.ReadFile(filepath.Join("testdata", "golden2", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s %s: content mismatch (%d vs %d)", first, name, len(got), len(want))
		}
	}
}

func TestVolumesRAR4New(t *testing.T) {
	checkVolumes(t, "t4mv.part01.rar")
}

func TestVolumesRAR4Old(t *testing.T) {
	checkVolumes(t, "t4mvo.rar")
}

func TestVolumesRAR4Solid(t *testing.T) {
	checkVolumes(t, "t4mvs.part01.rar")
}

func TestVolumesRAR5(t *testing.T) {
	checkVolumes(t, "t5mv.part01.rar")
}

func TestVolumesRAR5Solid(t *testing.T) {
	checkVolumes(t, "t5mvs.part01.rar")
}

func TestVolumesEncrypted(t *testing.T) {
	checkVolumes(t, "t4mve.part01.rar", WithPassword("secret"))
	checkVolumes(t, "t5mve.part01.rar", WithPassword("secret"))
}

func TestMissingVolume(t *testing.T) {
	dir := t.TempDir()
	// 拷 t5mv 全卷，删中间一卷。
	entries, err := filepath.Glob(filepath.Join("testdata", "t5mv.part*.rar"))
	if err != nil || len(entries) < 3 {
		t.Fatalf("glob: %v %d", err, len(entries))
	}
	for i, e := range entries {
		if i == 2 {
			continue // 缺 part03。
		}
		b, err := os.ReadFile(e)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(e)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, err = OpenReader(filepath.Join(dir, "t5mv.part01.rar"))
	if !errors.Is(err, ErrMissingVolume) {
		t.Fatalf("OpenReader = %v, want ErrMissingVolume", err)
	} else {
		t.Logf("missing: %v", err)
	}
}

func TestNotFirstVolume(t *testing.T) {
	_, err := OpenReader(filepath.Join("testdata", "t5mv.part03.rar"))
	if !errors.Is(err, ErrMissingVolume) {
		t.Fatalf("OpenReader(part03) = %v, want ErrMissingVolume", err)
	}
	_, err = OpenReader(filepath.Join("testdata", "t4mv.part03.rar"))
	if !errors.Is(err, ErrMissingVolume) {
		t.Fatalf("OpenReader(part03) = %v, want ErrMissingVolume", err)
	}
}
