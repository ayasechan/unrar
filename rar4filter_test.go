package rar

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

var filterFiles = []string{"ls", "cat", "tone.wav", "grad.rgb", "music.wav", "pic.bmp"}

func checkFilters(t *testing.T, arc string) {
	t.Helper()
	r, err := OpenReader(filepath.Join("testdata", arc))
	if err != nil {
		t.Fatalf("OpenReader(%s): %v", arc, err)
	}
	defer r.Close()
	for _, name := range filterFiles {
		var found *File
		for _, f := range r.File {
			if f.Name == name {
				found = f
			}
		}
		if found == nil {
			continue // 本夹具未收录该文件。
		}
		if found.IsDir {
			continue
		}
		rc, err := found.Open()
		if err != nil {
			t.Fatalf("%s Open(%s): %v", arc, name, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s Read(%s): %v", arc, name, err)
		}
		want, err := os.ReadFile(filepath.Join("testdata", "golden3", name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s %s: content mismatch (%d vs %d bytes)", arc, name, len(got), len(want))
		}
	}
}

func TestFiltersEXE(t *testing.T) {
	checkFilters(t, "t4fexe.rar")
}

func TestFiltersMedia(t *testing.T) {
	checkFilters(t, "t4fmedia.rar")
}

func TestFiltersMedia2(t *testing.T) {
	checkFilters(t, "t4fmedia2.rar")
}
