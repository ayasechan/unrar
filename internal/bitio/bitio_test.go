package bitio

import (
	"bytes"
	"testing"
)

func TestGetAddBits(t *testing.T) {
	r := NewReader(bytes.NewReader([]byte{0xAB, 0xCD, 0xEF, 0x12, 0x34}))
	if !r.Refill() {
		t.Fatal("refill")
	}
	if got := r.GetBits(); got != 0xABCD {
		t.Fatalf("peek = %04x", got)
	}
	r.AddBits(4)
	if got := r.GetBits(); got != 0xBCDE {
		t.Fatalf("peek = %04x", got)
	}
	r.AddBits(8)
	if got := r.GetBits(); got != 0xDEF1 {
		t.Fatalf("peek = %04x", got)
	}
}

func TestRefillCompacts(t *testing.T) {
	data := make([]byte, MaxSize+100)
	for i := range data {
		data[i] = byte(i)
	}
	r := NewReader(bytes.NewReader(data))
	if !r.Refill() {
		t.Fatal("refill1")
	}
	r.InAddr = MaxSize/2 + 1
	if !r.Refill() {
		t.Fatal("refill2")
	}
	if r.InAddr != 0 {
		t.Fatalf("InAddr = %d", r.InAddr)
	}
}
