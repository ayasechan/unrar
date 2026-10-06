package rarvm

import (
	"slices"
	"testing"
)

func runFilter(t *testing.T, typ FilterType, initR [7]uint32, input []byte) []byte {
	t.Helper()
	v := &VM{}
	v.Init()
	copy(v.Mem, input)
	prg := &Program{Type: typ, InitR: initR}
	v.Execute(prg)
	out, size := prg.Filtered()
	if uint32(len(out)) < size {
		t.Fatalf("short output: %d < %d", len(out), size)
	}
	return slices.Clone(out[:size])
}

func TestE8(t *testing.T) {
	// E8 10 00 00 00，FileOffset=0x100：addr=0x10 < 16M → addr-offset。
	got := runFilter(t, FilterE8, [7]uint32{0, 0, 0, 0, 6, 0, 0x100},
		[]byte{0xe8, 0x10, 0x00, 0x00, 0x00, 0x90})
	want := []byte{0xe8, 0x0f, 0xff, 0xff, 0xff, 0x90}
	if !slices.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
}

func TestE8E9(t *testing.T) {
	// E9 同规则；E8 在 E8E9 模式同样处理。
	got := runFilter(t, FilterE8E9, [7]uint32{0, 0, 0, 0, 6, 0, 0x100},
		[]byte{0xe9, 0x10, 0x00, 0x00, 0x00, 0x90})
	want := []byte{0xe9, 0x0f, 0xff, 0xff, 0xff, 0x90}
	if !slices.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	// 负 addr 分支：addr=0xFFFFFF00，offset=0x101 相加回绕为正 → +16M。
	got = runFilter(t, FilterE8, [7]uint32{0, 0, 0, 0, 6, 0, 0x100},
		[]byte{0xe8, 0x00, 0xff, 0xff, 0xff, 0x90})
	want = []byte{0xe8, 0x00, 0xff, 0xff, 0x00, 0x90}
	if !slices.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
}

func TestDelta(t *testing.T) {
	// 2 通道，SrcPos 全局推进：ch0 用 src0,1，ch1 用 src2,3。
	got := runFilter(t, FilterDelta, [7]uint32{2, 0, 0, 0, 4, 0, 0},
		[]byte{1, 2, 3, 4})
	want := []byte{255, 253, 253, 249}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRGB(t *testing.T) {
	// 6 字节 2 像素，Width=3，无上行预测；SrcData 跨通道连续推进。
	in := []byte{10, 20, 30, 40, 50, 60}
	got := runFilter(t, FilterRGB, [7]uint32{6, 0, 0, 0, 6, 0, 0}, in)
	want := []byte{216, 226, 176, 156, 186, 76}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestAudio(t *testing.T) {
	// 单通道 4 字节，K 自适应在 bc=0 不触发（Dif 全等）；手工验算。
	got := runFilter(t, FilterAudio, [7]uint32{1, 0, 0, 0, 4, 0, 0},
		[]byte{10, 20, 30, 40})
	want := []byte{246, 226, 196, 156}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestAudioStereo(t *testing.T) {
	// 双通道：SrcData 跨通道连续（ch0 取 src0,1，ch1 取 src2,3）；手工验算。
	got := runFilter(t, FilterAudio, [7]uint32{2, 0, 0, 0, 4, 0, 0},
		[]byte{10, 20, 30, 40})
	want := []byte{246, 226, 226, 186}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestItanium(t *testing.T) {
	mem := make([]byte, 64)
	mem[0] = 0x10
	mem[12], mem[13], mem[14], mem[15] = 0x50, 0x34, 0x23, 0x50
	got := runFilter(t, FilterItanium, [7]uint32{0, 0, 0, 0, 64, 0, 0x10}, mem)
	// offset 0x23345-1=0x23344：仅 bit0 变化，落在 byte12 高半字节。
	if got[12] != 0x40 || got[13] != 0x34 || got[14] != 0x23 || got[15] != 0x50 {
		t.Fatalf("bundle0 = %02x %02x %02x %02x", got[12], got[13], got[14], got[15])
	}
	for i, c := range got {
		if i >= 12 && i <= 15 {
			continue
		}
		if c != mem[i] {
			t.Fatalf("byte %d changed: %02x", i, c)
		}
	}
}

func TestPrepareIdentifiesStandard(t *testing.T) {
	// Prepare 仅做识别：未知码保持 FilterNone。
	v := &VM{}
	prg := &Program{}
	v.Prepare([]byte{0x00, 0x01, 0x02}, prg)
	if prg.Type != FilterNone {
		t.Fatalf("type = %v", prg.Type)
	}
	// 坏校验和同样拒绝。
	prg2 := &Program{}
	v.Prepare(make([]byte, 53), prg2)
	if prg2.Type != FilterNone {
		t.Fatalf("type = %v", prg2.Type)
	}
}
