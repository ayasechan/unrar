package rar

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

var compressedFiles = []string{"exeish.bin", "text.txt", "sub/n2.txt"}

func checkCompressed(t *testing.T, arc string, version int) {
	t.Helper()
	r, err := OpenReader(filepath.Join("testdata", arc))
	if err != nil {
		t.Fatalf("OpenReader(%s): %v", arc, err)
	}
	defer r.Close()
	if r.Version != version {
		t.Fatalf("%s version = %d", arc, r.Version)
	}
	for _, name := range compressedFiles {
		var found *File
		for _, f := range r.File {
			if f.Name == name {
				found = f
			}
		}
		if found == nil {
			t.Fatalf("%s: missing %q", arc, name)
		}
		t.Logf("%s %s: method=%d unpVer=%d solid=%v size=%d", arc, name, found.data.method, found.data.unpVer, found.Solid, found.UnpackedSize)
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

func TestCompressedRAR4(t *testing.T) {
	for _, m := range []string{"t4m1.rar", "t4m2.rar", "t4m3.rar", "t4m4.rar", "t4m5.rar", "t4d64k.rar"} {
		checkCompressed(t, m, 4)
	}
}

func TestCompressedRAR4Solid(t *testing.T) {
	checkCompressed(t, "t4m5s.rar", 4)
}
