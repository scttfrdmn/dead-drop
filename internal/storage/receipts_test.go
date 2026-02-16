package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewReceiptManager_WithoutMasterKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "receipt.key")

	rm, err := NewReceiptManager(keyPath, nil)
	if err != nil {
		t.Fatalf("NewReceiptManager error: %v", err)
	}
	if len(rm.secret) != 32 {
		t.Errorf("secret length = %d, want 32", len(rm.secret))
	}

	// Key file should exist
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("key file should be created")
	}
}

func TestNewReceiptManager_KeyPersistence(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "receipt.key")

	rm1, err := NewReceiptManager(keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	rm2, err := NewReceiptManager(keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	if string(rm1.secret) != string(rm2.secret) {
		t.Error("reloaded key should match original")
	}
}

func TestReceiptManager_Generate_Deterministic(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "receipt.key")

	rm, _ := NewReceiptManager(keyPath, nil)

	r1 := rm.Generate("drop-id-1")
	r2 := rm.Generate("drop-id-1")

	if r1 != r2 {
		t.Errorf("same dropID should produce same receipt: %q != %q", r1, r2)
	}
}

func TestReceiptManager_Generate_UniquePerDrop(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "receipt.key")

	rm, _ := NewReceiptManager(keyPath, nil)

	r1 := rm.Generate("drop-1")
	r2 := rm.Generate("drop-2")

	if r1 == r2 {
		t.Error("different dropIDs should produce different receipts")
	}
}

func TestReceiptManager_Validate_Correct(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "receipt.key")

	rm, _ := NewReceiptManager(keyPath, nil)
	dropID := "test-drop-id"
	receipt := rm.Generate(dropID)

	if !rm.Validate(dropID, receipt) {
		t.Error("correct receipt should validate")
	}
}

func TestReceiptManager_Validate_Wrong(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "receipt.key")

	rm, _ := NewReceiptManager(keyPath, nil)
	dropID := "test-drop-id"

	if rm.Validate(dropID, "wrong-receipt") {
		t.Error("wrong receipt should not validate")
	}
}

func TestReceiptManager_Validate_WrongDropID(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "receipt.key")

	rm, _ := NewReceiptManager(keyPath, nil)
	receipt := rm.Generate("drop-1")

	if rm.Validate("drop-2", receipt) {
		t.Error("receipt for different drop should not validate")
	}
}

func TestNewReceiptManager_WithMasterKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "receipt.key")

	// Use a 32-byte master key (as would come from DeriveMasterKey)
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	rm1, err := NewReceiptManager(keyPath, masterKey)
	if err != nil {
		t.Fatal(err)
	}

	rm2, err := NewReceiptManager(keyPath, masterKey)
	if err != nil {
		t.Fatal(err)
	}

	if string(rm1.secret) != string(rm2.secret) {
		t.Error("encrypted key reload should produce same secret")
	}

	// Receipt should be valid across reloads
	receipt := rm1.Generate("test")
	if !rm2.Validate("test", receipt) {
		t.Error("receipt should validate across reloads")
	}
}
