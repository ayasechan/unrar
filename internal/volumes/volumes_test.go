package volumes

import "testing"

func TestNewStyle(t *testing.T) {
	got, err := Sibling("a.part01.rar", 3)
	if err != nil || got != "a.part03.rar" {
		t.Fatalf("got %q err %v", got, err)
	}
	if IndexOf("a.part01.rar", "a.part03.rar") != 3 {
		t.Fatal("IndexOf mismatch")
	}
	if IndexOf("a.part01.rar", "a.part3.rar") != -1 {
		t.Fatal("width must match")
	}
}

func TestOldStyle(t *testing.T) {
	got, err := Sibling("a.rar", 2)
	if err != nil || got != "a.r00" {
		t.Fatalf("got %q err %v", got, err)
	}
	got, err = Sibling("a.rar", 3)
	if err != nil || got != "a.r01" {
		t.Fatalf("got %q err %v", got, err)
	}
	if IndexOf("a.rar", "a.r01") != 3 {
		t.Fatal("IndexOf mismatch")
	}
	if IndexOf("a.rar", "b.r01") != -1 {
		t.Fatal("base must match")
	}
}
