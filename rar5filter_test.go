package rar

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

var filter5Files = []string{"ls", "cat", "tone.wav", "grad.rgb", "music.wav", "pic.bmp"}

func checkFilters5(t *testing.T, arc string) {
	t.Helper()
	r, err := OpenReader(filepath.Join("testdata", arc))
	if err != nil {
		t.Fatalf("OpenReader(%s): %v", arc, err)
	}
	defer r.Close()
	for _, name := range filter5Files {
		var found *File
		for _, f := range r.File {
			if f.Name == name {
				found = f
			}
		}
		if found == nil {
			continue
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

func TestFilters5EXE(t *testing.T) {
	checkFilters5(t, "t5fexe.rar")
}

func TestFilters5Media(t *testing.T) {
	checkFilters5(t, "t5fmedia.rar")
}
