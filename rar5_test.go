package rar

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

var compressed5Files = []string{"exeish.bin", "text.txt", "sub/n2.txt"}

func checkCompressed5(t *testing.T, arc string) {
	t.Helper()
	r, err := OpenReader(filepath.Join("testdata", arc))
	if err != nil {
		t.Fatalf("OpenReader(%s): %v", arc, err)
	}
	defer r.Close()
	if r.Version != 5 {
		t.Fatalf("%s version = %d", arc, r.Version)
	}
	for _, name := range compressed5Files {
		var found *File
		for _, f := range r.File {
			if f.Name == name {
				found = f
			}
		}
		if found == nil {
			t.Fatalf("%s: missing %q", arc, name)
		}
		t.Logf("%s %s: method=%d unpVer=%d solid=%v size=%d win=%d", arc, name,
			found.data.method, found.data.unpVer, found.Solid, found.UnpackedSize, found.data.winSize)
		rc, err := found.Open()
		if err != nil {
			t.Fatalf("%s Open(%s): %v", arc, name, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s Read(%s): %v", arc, name, err)
		}
		want, err := os.ReadFile(filepath.Join("testdata", "golden2", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s %s: content mismatch (%d vs %d bytes)", arc, name, len(got), len(want))
		}
	}
}

func TestCompressedRAR5(t *testing.T) {
	for _, m := range []string{"t5m1.rar", "t5m2.rar", "t5m3.rar", "t5m4.rar", "t5m5.rar"} {
		checkCompressed5(t, m)
	}
}

func TestCompressedRAR5Solid(t *testing.T) {
	checkCompressed5(t, "t5m5s.rar")
}

func TestCompressedRAR5Dict4M(t *testing.T) {
	checkCompressed5(t, "t5d4m.rar")
}

func TestCompressedRAR5Book(t *testing.T) {
	for _, arc := range []string{"t5book.rar"} {
		r, err := OpenReader(filepath.Join("testdata", arc))
		if err != nil {
			t.Fatal(err)
		}
		if len(r.File) != 1 || r.File[0].Name != "book.txt" {
			t.Fatalf("%s files = %v", arc, names(r))
		}
		t.Logf("%s win=%d", arc, r.File[0].data.winSize)
		rc, err := r.File[0].Open()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		r.Close()
		if err != nil {
			t.Fatalf("%s: %v", arc, err)
		}
		want, err := os.ReadFile(filepath.Join("testdata", "golden3", "book.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s content mismatch (%d vs %d bytes)", arc, len(got), len(want))
		}
	}
}
