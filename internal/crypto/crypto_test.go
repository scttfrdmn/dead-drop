package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte %d not zeroed: got %d", i, v)
		}
	}
}

func TestZeroBytes_Empty(t *testing.T) {
	b := []byte{}
	ZeroBytes(b) // should not panic
}

func TestZeroBytes_Nil(t *testing.T) {
	ZeroBytes(nil) // should not panic
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestGenerateKey_Uniqueness(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key2, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key1, key2) {
		t.Error("two generated keys are identical")
	}
}

func TestEncryptDecryptStream_RoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello, dead drop!")
	aad := []byte("drop-id-123")

	var cipherBuf bytes.Buffer
	if err := EncryptStream(key, bytes.NewReader(plaintext), &cipherBuf, aad); err != nil {
		t.Fatalf("EncryptStream error: %v", err)
	}

	var decBuf bytes.Buffer
	if err := DecryptStream(key, &cipherBuf, &decBuf, aad); err != nil {
		t.Fatalf("DecryptStream error: %v", err)
	}

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Errorf("decrypted = %q, want %q", decBuf.Bytes(), plaintext)
	}
}

func TestEncryptDecryptStream_EmptyData(t *testing.T) {
	key, _ := GenerateKey()
	aad := []byte("test")

	var cipherBuf bytes.Buffer
	if err := EncryptStream(key, bytes.NewReader(nil), &cipherBuf, aad); err != nil {
		t.Fatalf("EncryptStream error: %v", err)
	}

	var decBuf bytes.Buffer
	if err := DecryptStream(key, &cipherBuf, &decBuf, aad); err != nil {
		t.Fatalf("DecryptStream error: %v", err)
	}

	if len(decBuf.Bytes()) != 0 {
		t.Errorf("decrypted length = %d, want 0", len(decBuf.Bytes()))
	}
}

func TestEncryptDecryptStream_NilAAD(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("no aad")

	var cipherBuf bytes.Buffer
	if err := EncryptStream(key, bytes.NewReader(plaintext), &cipherBuf, nil); err != nil {
		t.Fatalf("EncryptStream error: %v", err)
	}

	var decBuf bytes.Buffer
	if err := DecryptStream(key, &cipherBuf, &decBuf, nil); err != nil {
		t.Fatalf("DecryptStream error: %v", err)
	}

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Errorf("decrypted = %q, want %q", decBuf.Bytes(), plaintext)
	}
}

func TestDecryptStream_AADMismatch(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("secret data")

	var cipherBuf bytes.Buffer
	if err := EncryptStream(key, bytes.NewReader(plaintext), &cipherBuf, []byte("aad-1")); err != nil {
		t.Fatal(err)
	}

	var decBuf bytes.Buffer
	err := DecryptStream(key, &cipherBuf, &decBuf, []byte("aad-2"))
	if err == nil {
		t.Fatal("expected error when AAD does not match, got nil")
	}
}

func TestDecryptStream_WrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	plaintext := []byte("secret")

	var cipherBuf bytes.Buffer
	if err := EncryptStream(key1, bytes.NewReader(plaintext), &cipherBuf, nil); err != nil {
		t.Fatal(err)
	}

	var decBuf bytes.Buffer
	err := DecryptStream(key2, &cipherBuf, &decBuf, nil)
	if err == nil {
		t.Fatal("expected error with wrong key, got nil")
	}
}

func TestDecryptStream_CorruptedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("test data")

	var cipherBuf bytes.Buffer
	if err := EncryptStream(key, bytes.NewReader(plaintext), &cipherBuf, nil); err != nil {
		t.Fatal(err)
	}

	data := cipherBuf.Bytes()
	// Flip a byte in the ciphertext (after nonce)
	if len(data) > 13 {
		data[13] ^= 0xFF
	}

	var decBuf bytes.Buffer
	err := DecryptStream(key, bytes.NewReader(data), &decBuf, nil)
	if err == nil {
		t.Fatal("expected error with corrupted ciphertext, got nil")
	}
}

func TestDecryptStream_TruncatedStream(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("test data that is longer than nonce")

	var cipherBuf bytes.Buffer
	if err := EncryptStream(key, bytes.NewReader(plaintext), &cipherBuf, nil); err != nil {
		t.Fatal(err)
	}

	// Truncate to just the nonce
	truncated := cipherBuf.Bytes()[:12]

	var decBuf bytes.Buffer
	err := DecryptStream(key, bytes.NewReader(truncated), &decBuf, nil)
	if err == nil {
		t.Fatal("expected error with truncated stream, got nil")
	}
}

func TestDecryptStream_TooShortForNonce(t *testing.T) {
	key, _ := GenerateKey()

	var decBuf bytes.Buffer
	err := DecryptStream(key, bytes.NewReader([]byte{1, 2, 3}), &decBuf, nil)
	if err == nil {
		t.Fatal("expected error with data too short for nonce")
	}
}

func TestEncryptStream_NonceUniqueness(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("same data")

	var buf1, buf2 bytes.Buffer
	if err := EncryptStream(key, bytes.NewReader(plaintext), &buf1, nil); err != nil {
		t.Fatal(err)
	}
	if err := EncryptStream(key, bytes.NewReader(plaintext), &buf2, nil); err != nil {
		t.Fatal(err)
	}

	// Nonces are the first 12 bytes
	nonce1 := buf1.Bytes()[:12]
	nonce2 := buf2.Bytes()[:12]
	if bytes.Equal(nonce1, nonce2) {
		t.Error("two encryptions produced the same nonce")
	}
}

func TestEncryptStream_LargeData(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := make([]byte, 1024*1024) // 1MB
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatal(err)
	}

	var cipherBuf bytes.Buffer
	if err := EncryptStream(key, bytes.NewReader(plaintext), &cipherBuf, []byte("big")); err != nil {
		t.Fatal(err)
	}

	var decBuf bytes.Buffer
	if err := DecryptStream(key, &cipherBuf, &decBuf, []byte("big")); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Error("large data round-trip failed")
	}
}

func TestEncryptStream_InvalidKeyLength(t *testing.T) {
	shortKey := []byte("too-short")
	var buf bytes.Buffer
	err := EncryptStream(shortKey, bytes.NewReader([]byte("data")), &buf, nil)
	if err == nil {
		t.Fatal("expected error with invalid key length")
	}
}

func TestDecryptStream_InvalidKeyLength(t *testing.T) {
	shortKey := []byte("short")
	var buf bytes.Buffer
	err := DecryptStream(shortKey, bytes.NewReader([]byte("xxxxxxxxxxxx"+"data")), &buf, nil)
	if err == nil {
		t.Fatal("expected error with invalid key length")
	}
}

func FuzzEncryptDecrypt(f *testing.F) {
	f.Add([]byte("hello"), []byte("aad"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("x"), []byte("y"))

	key, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, plaintext, aad []byte) {
		var cipherBuf bytes.Buffer
		if err := EncryptStream(key, bytes.NewReader(plaintext), &cipherBuf, aad); err != nil {
			t.Fatal(err)
		}

		var decBuf bytes.Buffer
		if err := DecryptStream(key, &cipherBuf, &decBuf, aad); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(decBuf.Bytes(), plaintext) {
			t.Errorf("round-trip mismatch")
		}
	})
}
