package rar

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// FuzzReader 模糊解压入口：损坏输入只允许报错，不允许 panic/挂起。
// 语料：testdata 下各格式首卷（含分卷首卷）。
func FuzzReader(f *testing.F) {
	seeds := []string{
		"t4store.rar", "t5store.rar", "t4m1.rar", "t5m1.rar",
		"t4m5s.rar", "t5m5s.rar", "t4ppm.rar", "t4fexe.rar",
		"t4mv.part01.rar", "t5mv.part01.rar",
		"t4p.rar", "t5p.rar",
	}
	for _, s := range seeds {
		b, err := os.ReadFile(filepath.Join("testdata", s))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		r, err := NewReader(MemVolumes{Names: []string{"m.rar"}, Data: map[string][]byte{"m.rar": data}})
		if err != nil {
			return
		}
		defer r.Close()
		for _, file := range r.File {
			if file.IsDir {
				continue
			}
			rc, err := file.Open()
			if err != nil {
				continue
			}
			// 限读防炸弹拖慢 fuzz。
			_, _ = io.CopyN(io.Discard, rc, 4<<20)
			rc.Close()
		}
	})
}
