// Package rs16 实现 RAR5 恢复卷的 Reed-Solomon 编解码（GF(2^16) Cauchy 矩阵）。
package rs16

import "sync"

const gfSize = 65535

var (
	gfExp  []uint
	gfLog  []uint
	gfOnce sync.Once
)

func gfInitTables() {
	gfOnce.Do(func() {
		gfExp = make([]uint, 4*gfSize+1)
		gfLog = make([]uint, gfSize+1)
		for l, e := uint(0), uint(1); l < gfSize; l++ {
			gfLog[e] = l
			gfExp[l] = e
			gfExp[l+gfSize] = e
			e <<= 1
			if e > gfSize {
				e ^= 0x1100B
			}
		}
		gfLog[0] = 2 * gfSize
		for i := uint(2 * gfSize); i <= 4*gfSize; i++ {
			gfExp[i] = 0
		}
	})
}

func gfMul(a, b uint) uint { return gfExp[gfLog[a]+gfLog[b]] }
func gfInv(a uint) uint {
	if a == 0 {
		return 0
	}
	return gfExp[gfSize-gfLog[a]]
}

// Coder 是 RS16 编解码器（单例复用表，实例存矩阵）。
type Coder struct {
	nd, nr, ne uint
	decoding   bool
	valid      []bool
	mx         []uint
	dataLog    []uint
}

// Init 初始化。valid 为 nil 表编码，否则为解码（每单元有效标志）。
func (c *Coder) Init(dataCount, recCount uint, valid []bool) bool {
	gfInitTables()
	c.nd, c.nr, c.ne = dataCount, recCount, 0
	c.decoding = valid != nil
	if c.decoding {
		c.valid = append([]bool(nil), valid...)
		for i := uint(0); i < dataCount; i++ {
			if !c.valid[i] {
				c.ne++
			}
		}
		var validECC uint
		for i := dataCount; i < dataCount+recCount; i++ {
			if c.valid[i] {
				validECC++
			}
		}
		if c.ne > validECC || c.ne == 0 || validECC == 0 {
			return false
		}
	}
	if dataCount+recCount > gfSize || dataCount == 0 || recCount == 0 {
		return false
	}
	if c.decoding {
		c.mx = make([]uint, c.ne*dataCount)
		c.makeDecoderMatrix()
		c.invertDecoderMatrix()
	} else {
		c.mx = make([]uint, recCount*dataCount)
		c.makeEncoderMatrix()
	}
	return true
}

func (c *Coder) makeEncoderMatrix() {
	for i := uint(0); i < c.nr; i++ {
		for j := uint(0); j < c.nd; j++ {
			c.mx[i*c.nd+j] = gfInv((i + c.nd) ^ j)
		}
	}
}

func (c *Coder) makeDecoderMatrix() {
	var flag, r, dest uint = 0, c.nd, 0
	for ; flag < c.nd; flag++ {
		if !c.valid[flag] {
			for ; !c.valid[r]; r++ {
			}
			for j := uint(0); j < c.nd; j++ {
				c.mx[dest*c.nd+j] = gfInv(r ^ j)
			}
			dest++
			r++
		}
	}
}

// invertDecoderMatrix 对 NE×ND 解码矩阵求逆（Gauss-Jordan，跳过平凡行）。
func (c *Coder) invertDecoderMatrix() {
	mi := make([]uint, c.ne*c.nd)
	// 单位矩阵（仅非平凡列）。
	for kr, kf := uint(0), uint(0); kr < c.ne; kr, kf = kr+1, kf+1 {
		for kf < c.nd && c.valid[kf] {
			kf++
		}
		mi[kr*c.nd+kf] = 1
	}
	for kr, kf := uint(0), uint(0); kf < c.nd; kr, kf = kr+1, kf+1 {
		for kf < c.nd && c.valid[kf] {
			for i := uint(0); i < c.ne; i++ {
				mi[i*c.nd+kf] ^= c.mx[i*c.nd+kf]
			}
			kf++
		}
		if kf == c.nd {
			break
		}
		mxk := c.mx[kr*c.nd : (kr+1)*c.nd]
		mik := mi[kr*c.nd : (kr+1)*c.nd]
		pinv := gfInv(mxk[kf])
		for i := uint(0); i < c.nd; i++ {
			mxk[i] = gfMul(mxk[i], pinv)
			mik[i] = gfMul(mik[i], pinv)
		}
		for i := uint(0); i < c.ne; i++ {
			if i == kr {
				continue
			}
			mxi := c.mx[i*c.nd : (i+1)*c.nd]
			mii := mi[i*c.nd : (i+1)*c.nd]
			factor := mxi[kf]
			for j := uint(0); j < c.nd; j++ {
				mxi[j] ^= gfMul(mxk[j], factor)
				mii[j] ^= gfMul(mik[j], factor)
			}
		}
	}
	copy(c.mx, mi)
}

// UpdateECC 把一个数据块累加到一个 ECC 块（编解码通用）。
// BlockSize 须为偶数（调用方保证，与参考一致）。
func (c *Coder) UpdateECC(dataNum, eccNum uint, data, ecc []byte, blockSize int) {
	if dataNum == 0 {
		for i := 0; i < blockSize && i < len(ecc); i++ {
			ecc[i] = 0
		}
	}
	if eccNum == 0 {
		if len(c.dataLog) != blockSize {
			c.dataLog = make([]uint, blockSize)
		}
		for i := 0; i+1 < blockSize; i += 2 {
			c.dataLog[i] = gfLog[uint(data[i])|uint(data[i+1])<<8]
		}
	}
	ml := gfLog[c.mx[eccNum*c.nd+dataNum]]
	for i := 0; i+1 < blockSize; i += 2 {
		r := gfExp[ml+c.dataLog[i]]
		ecc[i] ^= byte(r)
		ecc[i+1] ^= byte(r >> 8)
	}
}
