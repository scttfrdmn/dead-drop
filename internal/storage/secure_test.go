package storage

import (
	"encoding/hex"
	"testing"
)

func TestValidateDropID_Valid(t *testing.T) {
	if err := ValidateDropID("abcdef0123456789abcdef0123456789"); err != nil {
		t.Errorf("valid ID rejected: %v", err)
	}
}

func TestValidateDropID_PathTraversal(t *testing.T) {
	ids := []string{
		"../../../etc/passwd",
		"./abcdef0123456789abcdef01234567",
		"/etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
	}
	for _, id := range ids {
		if err := ValidateDropID(id); err == nil {
			t.Errorf("path traversal ID %q should be rejected", id)
		}
	}
}

func TestValidateDropID_WrongLength(t *testing.T) {
	ids := []string{
		"abcdef",                                    // too short
		"abcdef0123456789abcdef0123456789abcdef01", // too long
		"",
	}
	for _, id := range ids {
		if err := ValidateDropID(id); err == nil {
			t.Errorf("ID %q (len=%d) should be rejected", id, len(id))
		}
	}
}

func TestValidateDropID_NonHexChars(t *testing.T) {
	ids := []string{
		"ABCDEF0123456789ABCDEF0123456789", // uppercase
		"abcdef012345678gabcdef0123456789",  // 'g'
		"abcdef0123456789abcdef012345678!",  // special char
	}
	for _, id := range ids {
		if err := ValidateDropID(id); err == nil {
			t.Errorf("non-hex ID %q should be rejected", id)
		}
	}
}

func TestConstantTimeCompare_Equal(t *testing.T) {
	if !ConstantTimeCompare("hello", "hello") {
		t.Error("equal strings should return true")
	}
}

func TestConstantTimeCompare_NotEqual(t *testing.T) {
	if ConstantTimeCompare("hello", "world") {
		t.Error("different strings should return false")
	}
}

func TestConstantTimeCompare_DifferentLengths(t *testing.T) {
	if ConstantTimeCompare("short", "longer string") {
		t.Error("different length strings should return false")
	}
}

func TestConstantTimeCompare_Empty(t *testing.T) {
	if !ConstantTimeCompare("", "") {
		t.Error("two empty strings should be equal")
	}
}

func TestSecureRandom_Length(t *testing.T) {
	for _, n := range []int{1, 16, 32, 64} {
		b, err := SecureRandom(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != n {
			t.Errorf("SecureRandom(%d) length = %d", n, len(b))
		}
	}
}

func TestSecureRandom_Uniqueness(t *testing.T) {
	b1, _ := SecureRandom(32)
	b2, _ := SecureRandom(32)
	if string(b1) == string(b2) {
		t.Error("two random outputs should differ")
	}
}

func TestSecureRandomHex_Format(t *testing.T) {
	s, err := SecureRandomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 32 {
		t.Errorf("hex length = %d, want 32", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Errorf("not valid hex: %v", err)
	}
}

func TestSecureRandomHex_Uniqueness(t *testing.T) {
	s1, _ := SecureRandomHex(16)
	s2, _ := SecureRandomHex(16)
	if s1 == s2 {
		t.Error("two hex outputs should differ")
	}
}

func TestZeroBytes_Storage(t *testing.T) {
	b := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte %d = %x, want 0", i, v)
		}
	}
}

func FuzzValidateDropID(f *testing.F) {
	f.Add("abcdef0123456789abcdef0123456789")
	f.Add("../../../etc/passwd")
	f.Add("")
	f.Add("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")

	f.Fuzz(func(t *testing.T, id string) {
		err := ValidateDropID(id)
		if err == nil {
			// If accepted, it must be exactly 32 lowercase hex chars
			if len(id) != 32 {
				t.Errorf("accepted ID with length %d", len(id))
			}
			if _, decErr := hex.DecodeString(id); decErr != nil {
				t.Errorf("accepted non-hex ID: %q", id)
			}
		}
	})
}
