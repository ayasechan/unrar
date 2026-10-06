// Package rs8 实现 RAR4 恢复卷的 Reed-Solomon 纠删码（GF(256)）。
package rs8

const (
	maxPar = 255
	maxPol = 512
	poly   = 0x11D
)

// Coder 是 RS8 编解码器（ParSize = 恢复卷数）。
type Coder struct {
	parSize  int
	gfExp    [maxPol]int
	gfLog    [maxPar + 1]int
	gxPol    [maxPol * 2]int
	errLocs  [maxPar + 1]int
	errCount int
	dnm      [maxPar + 1]int
	elPol    [maxPol]int
	first    bool
}

// Init 初始化（ParSize = 恢复卷数）。
func (c *Coder) Init(parSize int) {
	c.parSize = parSize
	c.first = false
	for i, j := 0, 1; i < maxPar; i++ {
		c.gfLog[j] = i
		c.gfExp[i] = j
		j <<= 1
		if j > maxPar {
			j ^= poly
		}
	}
	for i := maxPar; i < maxPol; i++ {
		c.gfExp[i] = c.gfExp[i-maxPar]
	}
	// 生成多项式 g(x)=(x-a)(x-a^2)...(x-a^N)。
	var p2 [maxPar + 1]int
	p2[0] = 1
	for i := 1; i <= parSize; i++ {
		var p1 [maxPar + 1]int
		p1[0] = c.gfExp[i]
		p1[1] = 1
		c.pnMult(p1[:], p2[:], c.gxPol[:])
		for j := 0; j < parSize; j++ {
			p2[j] = c.gxPol[j]
		}
	}
}

func (c *Coder) gfMult(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	return c.gfExp[c.gfLog[a]+c.gfLog[b]]
}

func (c *Coder) pnMult(p1, p2, r []int) {
	for i := range r[:c.parSize] {
		r[i] = 0
	}
	for i := 0; i < c.parSize; i++ {
		if p1[i] != 0 {
			for j := 0; j < c.parSize-i; j++ {
				r[i+j] ^= c.gfMult(p1[i], p2[j])
			}
		}
	}
}

// Encode 由数据算校验（创建恢复卷用，单测验证解码用）。
func (c *Coder) Encode(data []byte, dest []byte) {
	parSize := c.parSize
	var shift [maxPar + 1]int
	for _, d := range data {
		dv := int(d) ^ shift[parSize-1]
		for j := parSize - 1; j > 0; j-- {
			shift[j] = shift[j-1] ^ c.gfMult(c.gxPol[j], dv)
		}
		shift[0] = c.gfMult(c.gxPol[0], dv)
	}
	for i := 0; i < parSize; i++ {
		dest[i] = byte(shift[parSize-i-1])
	}
}

// Decode 以擦除位置纠删解码，成功返回 true。
// Data 长为数据卷+校验卷总数，EraLoc 为擦除槽位。
func (c *Coder) Decode(data []byte, dataSize int, eraLoc []int) bool {
	parSize := c.parSize
	if dataSize > maxPar || dataSize < 0 || len(data) < dataSize {
		return false
	}
	syn := make([]int, parSize)
	allZero := true
	for i := 0; i < parSize; i++ {
		sum := 0
		for j := 0; j < dataSize; j++ {
			sum = int(data[j]) ^ c.gfMult(c.gfExp[i+1], sum)
		}
		syn[i] = sum
		if sum != 0 {
			allZero = false
		}
	}
	if allZero {
		return true
	}
	if !c.first {
		c.first = true
		for i := range c.elPol {
			c.elPol[i] = 0
		}
		c.elPol[0] = 1
		for _, e := range eraLoc {
			m := c.gfExp[dataSize-e-1]
			for i := parSize; i > 0; i-- {
				c.elPol[i] ^= c.gfMult(m, c.elPol[i-1])
			}
		}
		c.errCount = 0
		for root := maxPar - dataSize; root < maxPar+1; root++ {
			sum := 0
			for b := 0; b < parSize+1; b++ {
				sum ^= c.gfMult(c.gfExp[(b*root)%maxPar], c.elPol[b])
			}
			if sum == 0 {
				loc := maxPar - root
				c.errLocs[c.errCount] = loc
				d := 0
				for i := 1; i < parSize+1; i += 2 {
					d ^= c.gfMult(c.elPol[i], c.gfExp[root*(i-1)%maxPar])
				}
				c.dnm[c.errCount] = d
				c.errCount++
			}
		}
	}
	var eePol [maxPol]int
	c.pnMult(c.elPol[:], syn, eePol[:])
	if c.errCount <= parSize && c.errCount > 0 {
		for i := 0; i < c.errCount; i++ {
			loc := c.errLocs[i]
			dloc := maxPar - loc
			n := 0
			for j := 0; j < parSize; j++ {
				n ^= c.gfMult(eePol[j], c.gfExp[dloc*j%maxPar])
			}
			pos := dataSize - loc - 1
			if pos >= 0 && pos < dataSize {
				data[pos] ^= byte(c.gfMult(n, c.gfExp[maxPar-c.gfLog[c.dnm[i]]]))
			}
		}
	}
	return c.errCount <= parSize
}
