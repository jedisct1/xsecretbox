package xsecretbox

import (
	"bytes"
	"testing"
)

func TestSecretbox(t *testing.T) {
	key := [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	nonce := [24]byte{23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	src := []byte{140, 141, 142, 143, 144, 145, 146, 147, 148, 149}
	expected := []byte{25, 114, 237, 248, 200, 53, 16, 193, 191, 225, 40, 120, 196, 190, 99, 230, 191, 167, 58, 195, 11, 125, 132, 23, 176, 194}

	dst := Seal(nil, nonce[:], src[:], key[:])

	if !bytes.Equal(expected, dst) {
		t.Errorf("got %x instead of %x", expected, dst)
	}

	dec, err := Open(nil, nonce[:], dst[:], key[:])
	if err != nil || !bytes.Equal(src, dec) {
		t.Errorf("got %x instead of %x", dec, src)
	}

	dst[0]++
	_, err = Open(nil, nonce[:], dst[:], key[:])
	if err == nil {
		t.Errorf("tag validation failed")
	}

	_, _ = SharedKey(key, key)
}

func TestSharedKey(t *testing.T) {
	pk := [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	sk := [32]byte{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41}
	expected := [32]byte{232, 47, 181, 56, 165, 130, 234, 207, 242, 65, 46, 117, 170, 172, 99, 173, 45, 8, 54, 163, 111, 2, 123, 52, 156, 119, 254, 132, 205, 210, 96, 217}
	shared, err := SharedKey(sk, pk)
	if err != nil {
		t.Errorf("got an error: %v", err)
	}
	if !bytes.Equal(expected[:], shared[:]) {
		t.Errorf("got %x instead of %x", expected, shared)
	}
}
