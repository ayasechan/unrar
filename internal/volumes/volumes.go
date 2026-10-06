// Package volumes 解析 RAR 新旧两种分卷命名并推导卷序列。
//
// 旧式（RAR4）：base.rar, base.r00, base.r01, ...
// 新式（RAR4/RAR5）：base.part01.rar, base.part02.rar, ...
package volumes

import (
	"fmt"
	"regexp"
	"strconv"
)

var newStyle = regexp.MustCompile(`^(.*)\.part(\d+)\.rar$`)

// Style 区分命名风格。
type Style int

const (
	StyleSingle Style = iota
	StyleOld
	StyleNew
)

// Detect 判定首卷名的命名风格。
func Detect(first string) Style {
	if m := newStyle.FindStringSubmatch(first); m != nil {
		return StyleNew
	}
	if len(first) > 4 && first[len(first)-4:] == ".rar" {
		return StyleOld
	}
	return StyleSingle
}

// Sibling 返回第 n 卷（1 起）的卷名。n=1 即首卷本身。
func Sibling(first string, n int) (string, error) {
	if n < 1 {
		return "", fmt.Errorf("volumes: bad index %d", n)
	}
	if m := newStyle.FindStringSubmatch(first); m != nil {
		width := len(m[2])
		return fmt.Sprintf("%s.part%0*d.rar", m[1], width, n), nil
	}
	if len(first) > 4 && first[len(first)-4:] == ".rar" {
		base := first[:len(first)-4]
		if n == 1 {
			return first, nil
		}
		return fmt.Sprintf("%s.r%02d", base, n-2), nil
	}
	if n == 1 {
		return first, nil
	}
	return "", fmt.Errorf("volumes: single archive has no volume %d", n)
}

// IndexOf 反查卷名序号（1 起），-1 表示不属于该序列。
func IndexOf(first, name string) int {
	if m := newStyle.FindStringSubmatch(first); m != nil {
		m2 := newStyle.FindStringSubmatch(name)
		if m2 == nil || m2[1] != m[1] || len(m2[2]) != len(m[2]) {
			return -1
		}
		n, err := strconv.Atoi(m2[2])
		if err != nil {
			return -1
		}
		return n
	}
	if len(first) > 4 && first[len(first)-4:] == ".rar" {
		base := first[:len(first)-4]
		if name == first {
			return 1
		}
		re := regexp.MustCompile(`^` + regexp.QuoteMeta(base) + `\.r(\d+)$`)
		m := re.FindStringSubmatch(name)
		if m == nil || len(m[1]) != 2 {
			return -1
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return -1
		}
		// 旧式要求恰好两位零填充：r00, r01, ...
		if len(m[1]) != 2 {
			return -1
		}
		return n + 2
	}
	if name == first {
		return 1
	}
	return -1
}
