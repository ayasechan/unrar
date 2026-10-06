package rar

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPPMText(t *testing.T) {
	r, err := OpenReader(filepath.Join("testdata", "t4ppm.rar"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.File) != 1 {
		t.Fatalf("files = %d", len(r.File))
	}
	f := r.File[0]
	if f.Name != "book.txt" {
		t.Fatalf("name = %q", f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "golden3", "book.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("content mismatch (%d vs %d bytes)", len(got), len(want))
	}
}
