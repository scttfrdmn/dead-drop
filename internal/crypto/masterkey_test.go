package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateSalt_CreateNew(t *testing.T) {
	dir := t.TempDir()
	salt, err := LoadOrGenerateSalt(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(salt) != saltSize {
		t.Fatalf("expected salt length %d, got %d", saltSize, len(salt))
	}

	// Verify file was written
	data, err := os.ReadFile(filepath.Join(dir, masterSaltFile))
	if err != nil {
		t.Fatalf("salt file not written: %v", err)
	}
	if !bytes.Equal(data, salt) {
		t.Fatal("salt file contents don't match returned salt")
	}
}

func TestLoadOrGenerateSalt_LoadExisting(t *testing.T) {
	dir := t.TempDir()

	// First call creates
	salt1, err := LoadOrGenerateSalt(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second call loads
	salt2, err := LoadOrGenerateSalt(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(salt1, salt2) {
		t.Fatal("salt changed between calls")
	}
}

func TestEncryptDecryptKeyFile_RoundTrip(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	plaintextKey := make([]byte, 32)
	for i := range plaintextKey {
		plaintextKey[i] = byte(i + 100)
	}

	encrypted, err := EncryptKeyFile(masterKey, plaintextKey)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if len(encrypted) != EncryptedKeySize {
		t.Fatalf("expected encrypted size %d, got %d", EncryptedKeySize, len(encrypted))
	}

	decrypted, err := DecryptKeyFile(masterKey, encrypted)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintextKey) {
		t.Fatal("decrypted key doesn't match original")
	}
}

func TestDecryptKeyFile_WrongMasterKey(t *testing.T) {
	masterKey := make([]byte, 32)
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF

	plaintextKey := make([]byte, 32)

	encrypted, err := EncryptKeyFile(masterKey, plaintextKey)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = DecryptKeyFile(wrongKey, encrypted)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDeriveMasterKey_Deterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")

	key1 := DeriveMasterKey("test-passphrase", salt)
	key2 := DeriveMasterKey("test-passphrase", salt)

	if !bytes.Equal(key1, key2) {
		t.Fatal("same passphrase+salt should produce same key")
	}

	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}
}

func TestDeriveMasterKey_DifferentPassphrase(t *testing.T) {
	salt := []byte("0123456789abcdef")

	key1 := DeriveMasterKey("passphrase-1", salt)
	key2 := DeriveMasterKey("passphrase-2", salt)

	if bytes.Equal(key1, key2) {
		t.Fatal("different passphrases should produce different keys")
	}
}

func TestDecryptKeyFile_TooShort(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := DecryptKeyFile(masterKey, []byte("short"))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}
