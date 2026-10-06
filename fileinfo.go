package rar

import (
	"io/fs"
	"time"
)

// fileInfo 把 File 适配为 fs.FileInfo。
type fileInfo struct{ f *File }

func (fi fileInfo) Name() string       { return fi.f.Name }
func (fi fileInfo) Size() int64        { return int64(fi.f.UnpackedSize) }
func (fi fileInfo) Mode() fs.FileMode  { return fi.f.Mode }
func (fi fileInfo) ModTime() time.Time { return fi.f.Modified }
func (fi fileInfo) IsDir() bool        { return fi.f.IsDir }
func (fi fileInfo) Sys() any           { return fi.f }
