// Package rarvm 实现 RAR3 标准过滤器虚拟机。
//
// RAR3 的全部过滤器都是 6 种标准过滤器之一（E8/E8E9/Itanium/Delta/RGB/Audio）。
// 流中携带的过滤器字节码仅用于以（长度，CRC32）识别类型，
// 真正的变换是 Go 原生实现的；未知字节码按无操作处理。
package rarvm

import (
	"encoding/binary"
	"hash/crc32"

	"github.com/ayasechan/unrar/internal/bitio"
)

// MemSize 是 VM 内存大小。
const MemSize = 0x40000

// MaxChannels 限制 Delta 通道数（防损坏数据拖慢）。
const MaxChannels = 1024

// FilterType 是标准过滤器类型。
type FilterType int

const (
	FilterNone FilterType = iota
	FilterE8
	FilterE8E9
	FilterItanium
	FilterRGB
	FilterAudio
	FilterDelta
)

type stdFilter struct {
	length uint
	crc    uint32
	typ    FilterType
}

var stdList = []stdFilter{
	{53, 0xad576887, FilterE8},
	{57, 0x3cd7e57e, FilterE8E9},
	{120, 0x3769893f, FilterItanium},
	{29, 0x0e06077d, FilterDelta},
	{149, 0x1c2c5dc8, FilterRGB},
	{216, 0xbc85e701, FilterAudio},
}

// Program 是预处理后的过滤器程序。
type Program struct {
	Type  FilterType
	InitR [7]uint32
	data  []byte // FilteredData 指向 VM 内存，本包外只读。
	size  uint32
}

// Filtered 返回最近一次 Execute 的输出。
func (p *Program) Filtered() ([]byte, uint32) { return p.data, p.size }

// VM 是过滤器虚拟机。
type VM struct {
	Mem []byte
	R   [8]uint32
}

// Init 分配内存（幂等）。
func (v *VM) Init() {
	if v.Mem == nil {
		v.Mem = make([]byte, MemSize+4)
	}
}

// Prepare 识别字节码对应的标准过滤器。未知码保持 FilterNone。
func (v *VM) Prepare(code []byte, prg *Program) {
	if len(code) == 0 {
		return
	}
	var xor byte
	for _, c := range code[1:] {
		xor ^= c
	}
	if xor != code[0] {
		return
	}
	c := crc32.Checksum(code, crc32.IEEETable)
	for _, s := range stdList {
		if s.crc == c && s.length == uint(len(code)) {
			prg.Type = s.typ
			return
		}
	}
}

// Execute 运行过滤器，输出指向 VM 内存。
func (v *VM) Execute(prg *Program) {
	v.Init()
	copy(v.R[:], prg.InitR[:])
	prg.data = nil
	prg.size = 0
	if prg.Type == FilterNone {
		return
	}
	ok := v.executeStandard(prg.Type)
	block := prg.InitR[4] & (MemSize - 1)
	prg.size = block
	switch prg.Type {
	case FilterDelta, FilterRGB, FilterAudio:
		if 2*block > MemSize || !ok {
			prg.data = v.Mem
		} else {
			prg.data = v.Mem[block:]
		}
	default:
		prg.data = v.Mem
	}
}

// SetMemory 拷贝数据到 VM 内存。
func (v *VM) SetMemory(pos uint64, data []byte) {
	if pos >= MemSize || len(data) == 0 {
		return
	}
	n := uint64(len(data))
	if n > MemSize-pos {
		n = MemSize - pos
	}
	copy(v.Mem[pos:pos+n], data[:n])
}

// ReadData 从位流读 VM 可变长整数。
func ReadData(br *bitio.Reader) uint32 {
	data := uint32(br.GetBits())
	switch data & 0xc000 {
	case 0:
		br.AddBits(6)
		return (data >> 10) & 0xf
	case 0x4000:
		if data&0x3c00 == 0 {
			data = 0xffffff00 | ((data >> 2) & 0xff)
			br.AddBits(14)
		} else {
			data = (data >> 6) & 0xff
			br.AddBits(10)
		}
		return data
	case 0x8000:
		br.AddBits(2)
		data = uint32(br.GetBits())
		br.AddBits(16)
		return data
	default:
		br.AddBits(2)
		data = uint32(br.GetBits()) << 16
		br.AddBits(16)
		data |= uint32(br.GetBits())
		br.AddBits(16)
		return data
	}
}

func abs32(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func (v *VM) executeStandard(t FilterType) bool {
	switch t {
	case FilterE8, FilterE8E9:
		return v.filterE8(t)
	case FilterItanium:
		return v.filterItanium()
	case FilterDelta:
		return v.filterDelta()
	case FilterRGB:
		return v.filterRGB()
	case FilterAudio:
		return v.filterAudio()
	}
	return false
}

// filterE8 处理 x86 CALL/JMP 重定位。
func (v *VM) filterE8(t FilterType) bool {
	const fileSize = 0x1000000
	dataSize, fileOffset := v.R[4], v.R[6]
	if dataSize > MemSize || dataSize < 4 {
		return false
	}
	cmp := byte(0xe8)
	if t == FilterE8E9 {
		cmp = 0xe9
	}
	mem := v.Mem
	pos := uint32(0)
	i := uint32(0)
	for pos < dataSize-4 {
		cur := mem[i]
		i++
		pos++
		if cur == 0xe8 || cur == cmp {
			offset := pos + fileOffset
			addr := binary.LittleEndian.Uint32(mem[i : i+4])
			if addr&0x80000000 != 0 {
				if (addr+offset)&0x80000000 == 0 {
					binary.LittleEndian.PutUint32(mem[i:i+4], addr+fileSize)
				}
			} else if (addr-fileSize)&0x80000000 != 0 {
				binary.LittleEndian.PutUint32(mem[i:i+4], addr-offset)
			}
			i += 4
			pos += 4
		}
	}
	return true
}

// filterItanium 处理 IA64 分支重定位。
func (v *VM) filterItanium() bool {
	dataSize, fileOffset := v.R[4], v.R[6]>>4
	if dataSize > MemSize || dataSize < 21 {
		return false
	}
	masks := [...]byte{4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0}
	mem := v.Mem
	off := uint32(0)
	curPos := uint32(0)
	for curPos < dataSize-21 {
		b := int(mem[off]&0x1f) - 0x10
		if b >= 0 {
			mask := masks[b]
			if mask != 0 {
				for s := uint32(0); s <= 2; s++ {
					if mask&(1<<s) != 0 {
						start := s*41 + 5
						if itaniumGetBits(mem[off:], start+37, 4) == 5 {
							o := itaniumGetBits(mem[off:], start+13, 20)
							itaniumSetBits(mem[off:], (o-fileOffset)&0xfffff, start+13, 20)
						}
					}
				}
			}
		}
		off += 16
		curPos += 16
		fileOffset++
	}
	return true
}

func itaniumGetBits(data []byte, bitPos, bitCount uint32) uint32 {
	addr := bitPos / 8
	bit := bitPos & 7
	field := uint32(data[addr]) | uint32(data[addr+1])<<8 | uint32(data[addr+2])<<16 | uint32(data[addr+3])<<24
	field >>= bit
	return field & (0xffffffff >> (32 - bitCount))
}

func itaniumSetBits(data []byte, field, bitPos, bitCount uint32) {
	addr := bitPos / 8
	bit := bitPos & 7
	mask := ^((0xffffffff >> (32 - bitCount)) << bit)
	field <<= bit
	for i := uint32(0); i < 4; i++ {
		data[addr+i] &= byte(mask)
		data[addr+i] |= byte(field)
		mask = (mask >> 8) | 0xff000000
		field >>= 8
	}
}

// filterDelta 还原差分编码（多通道交织）。
func (v *VM) filterDelta() bool {
	dataSize, channels := v.R[4], v.R[0]
	border := dataSize * 2
	if dataSize > MemSize/2 || channels > MaxChannels || channels == 0 {
		return false
	}
	mem := v.Mem
	src := uint32(0)
	for ch := uint32(0); ch < channels; ch++ {
		prev := byte(0)
		for dest := dataSize + ch; dest < border; dest += channels {
			prev -= mem[src]
			src++
			mem[dest] = prev
		}
	}
	return true
}

// filterRGB 还原图像预测编码。
func (v *VM) filterRGB() bool {
	dataSize := v.R[4]
	width := v.R[0] - 3
	posR := v.R[1]
	if dataSize > MemSize/2 || dataSize < 3 || width > dataSize || posR > 2 {
		return false
	}
	mem := v.Mem
	src := uint32(0)
	const channels = 3
	for ch := uint32(0); ch < channels; ch++ {
		var prev uint32
		for i := ch; i < dataSize; i += channels {
			var predicted uint32
			if i >= width+3 {
				upper := mem[dataSize+i-width]
				upperLeft := mem[dataSize+i-width-3]
				predicted = prev + uint32(upper) - uint32(upperLeft)
				pa := abs32(int(predicted) - int(prev))
				pb := abs32(int(predicted) - int(upper))
				pc := abs32(int(predicted) - int(upperLeft))
				switch {
				case pa <= pb && pa <= pc:
					predicted = prev
				case pb <= pc:
					predicted = uint32(upper)
				default:
					predicted = uint32(upperLeft)
				}
			} else {
				predicted = prev
			}
			v := byte(int(predicted) - int(mem[src]))
			src++
			mem[dataSize+i] = v
			prev = uint32(v)
		}
	}
	for i, border := posR, dataSize-2; i < border; i += 3 {
		g := mem[dataSize+i+1]
		mem[dataSize+i] += g
		mem[dataSize+i+2] += g
	}
	return true
}

// filterAudio 还原音频预测编码。
func (v *VM) filterAudio() bool {
	dataSize, channels := v.R[4], v.R[0]
	if dataSize > MemSize/2 || channels > 128 || channels == 0 {
		return false
	}
	mem := v.Mem
	src := uint32(0)
	for ch := uint32(0); ch < channels; ch++ {
		var prevByte uint32
		var prevDelta int
		var dif [7]uint32
		d1, d2 := 0, 0
		k1, k2, k3 := 0, 0, 0
		for i, bc := ch, uint32(0); i < dataSize; i, bc = i+channels, bc+1 {
			d3 := d2
			d2 = prevDelta - d1
			d1 = prevDelta
			// C++ uint 回绕语义，须用 uint32 运算。
			predicted := uint32(8*prevByte) + uint32(k1*d1) + uint32(k2*d2) + uint32(k3*d3)
			predicted = (predicted >> 3) & 0xff
			cur := mem[src]
			src++
			predicted -= uint32(cur)
			mem[dataSize+i] = byte(predicted)
			prevDelta = int(int8(predicted - prevByte))
			prevByte = predicted
			d := int(int32(uint32(int(int8(cur))) << 3))
			dif[0] += uint32(abs32(d))
			dif[1] += uint32(abs32(d - d1))
			dif[2] += uint32(abs32(d + d1))
			dif[3] += uint32(abs32(d - d2))
			dif[4] += uint32(abs32(d + d2))
			dif[5] += uint32(abs32(d - d3))
			dif[6] += uint32(abs32(d + d3))
			if bc&0x1f == 0 {
				minDif, numMin := dif[0], 0
				dif[0] = 0
				for j := 1; j < len(dif); j++ {
					if dif[j] < minDif {
						minDif, numMin = dif[j], j
					}
					dif[j] = 0
				}
				switch numMin {
				case 1:
					if k1 >= -16 {
						k1--
					}
				case 2:
					if k1 < 16 {
						k1++
					}
				case 3:
					if k2 >= -16 {
						k2--
					}
				case 4:
					if k2 < 16 {
						k2++
					}
				case 5:
					if k3 >= -16 {
						k3--
					}
				case 6:
					if k3 < 16 {
						k3++
					}
				}
			}
		}
	}
	return true
}
