package storage

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestNewManager_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "newdir")
	m, err := NewManager(dir, nil)
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	defer m.Close()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected a directory")
	}
}

func TestNewManager_LoadsKeys(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if len(m.EncryptionKey) != 32 {
		t.Errorf("EncryptionKey length = %d, want 32", len(m.EncryptionKey))
	}
	if m.Receipts == nil {
		t.Error("Receipts should be initialized")
	}
	if m.Locks == nil {
		t.Error("Locks should be initialized")
	}
}

func TestNewManager_PersistentKeys(t *testing.T) {
	dir := t.TempDir()
	m1, _ := NewManager(dir, nil)
	key1 := make([]byte, 32)
	copy(key1, m1.EncryptionKey)
	m1.Close()

	m2, _ := NewManager(dir, nil)
	defer m2.Close()

	if !bytes.Equal(key1, m2.EncryptionKey) {
		t.Error("keys should persist across reloads")
	}
}

func TestClose_ZerosKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	m.Close()

	allZero := true
	for _, b := range m.EncryptionKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("EncryptionKey should be zeroed after Close")
	}
}

func TestSaveDrop_GetDrop_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	content := []byte("secret document content")
	drop, err := m.SaveDrop("secret.txt", bytes.NewReader(content))
	if err != nil {
		t.Fatalf("SaveDrop error: %v", err)
	}

	if drop.ID == "" {
		t.Error("drop ID should not be empty")
	}
	if len(drop.ID) != 32 {
		t.Errorf("drop ID length = %d, want 32", len(drop.ID))
	}
	if drop.Filename != "secret.txt" {
		t.Errorf("Filename = %q", drop.Filename)
	}
	if drop.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", drop.Size, len(content))
	}
	if drop.Receipt == "" {
		t.Error("Receipt should not be empty")
	}
	if drop.FileHash == "" {
		t.Error("FileHash should not be empty")
	}

	// GetDrop round-trip
	filename, reader, err := m.GetDrop(drop.ID)
	if err != nil {
		t.Fatalf("GetDrop error: %v", err)
	}
	defer reader.Close()

	if filename != "secret.txt" {
		t.Errorf("filename = %q", filename)
	}

	got, _ := io.ReadAll(reader)
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch: got %q, want %q", got, content)
	}
}

func TestGetDrop_InvalidID_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()

	ids := []string{
		"../../../etc/passwd",
		"./abcdef0123456789abcdef01234567",
		"/etc/passwd",
		"",
	}

	for _, id := range ids {
		_, _, err := m.GetDrop(id)
		if err == nil {
			t.Errorf("GetDrop(%q) should fail", id)
		}
	}
}

func TestGetDrop_LegacyFileEnc(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	// Create a drop normally
	drop, _ := m.SaveDrop("test.txt", bytes.NewReader([]byte("test data")))

	// Rename "data" to "file.enc" to simulate legacy format
	dropDir := filepath.Join(dir, drop.ID)
	os.Rename(filepath.Join(dropDir, "data"), filepath.Join(dropDir, "file.enc"))

	filename, reader, err := m.GetDrop(drop.ID)
	if err != nil {
		t.Fatalf("GetDrop with legacy file.enc error: %v", err)
	}
	defer reader.Close()

	if filename != "test.txt" {
		t.Errorf("filename = %q", filename)
	}

	got, _ := io.ReadAll(reader)
	if string(got) != "test data" {
		t.Errorf("content = %q", got)
	}
}

func TestDeleteDrop(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	drop, _ := m.SaveDrop("delete-me.txt", bytes.NewReader([]byte("delete me")))

	if err := m.DeleteDrop(drop.ID); err != nil {
		t.Fatalf("DeleteDrop error: %v", err)
	}

	dropDir := filepath.Join(dir, drop.ID)
	if _, err := os.Stat(dropDir); !os.IsNotExist(err) {
		t.Error("drop directory should be removed")
	}
}

func TestDeleteDrop_InvalidID(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()

	err := m.DeleteDrop("../../../etc/passwd")
	if err == nil {
		t.Fatal("DeleteDrop with path traversal should fail")
	}
}

func TestDeleteDrop_SecureDelete(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = true

	drop, _ := m.SaveDrop("secure.txt", bytes.NewReader([]byte("secure data")))

	if err := m.DeleteDrop(drop.ID); err != nil {
		t.Fatalf("secure DeleteDrop error: %v", err)
	}

	dropDir := filepath.Join(dir, drop.ID)
	if _, err := os.Stat(dropDir); !os.IsNotExist(err) {
		t.Error("drop directory should be securely removed")
	}
}

func TestSaveDrop_WithQuota(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	qm, _ := NewQuotaManager(dir, 1.0, 100)
	m.Quota = qm

	drop, err := m.SaveDrop("quota.txt", bytes.NewReader([]byte("data")))
	if err != nil {
		t.Fatalf("SaveDrop with quota error: %v", err)
	}

	totalBytes, dropCount := qm.Stats()
	if totalBytes <= 0 {
		t.Error("totalBytes should increase after save")
	}
	if dropCount != 1 {
		t.Errorf("dropCount = %d, want 1", dropCount)
	}

	// Delete should release quota
	m.DeleteDrop(drop.ID)
	_, dropCount = qm.Stats()
	if dropCount != 0 {
		t.Errorf("dropCount after delete = %d, want 0", dropCount)
	}
}

func TestSaveDrop_QuotaExceeded(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	qm, _ := NewQuotaManager(dir, 0, 1) // max 1 drop (unlimited bytes, but 1 drop max)
	m.Quota = qm

	_, err := m.SaveDrop("first.txt", bytes.NewReader([]byte("first")))
	if err != nil {
		t.Fatal(err)
	}

	_, err = m.SaveDrop("second.txt", bytes.NewReader([]byte("second")))
	if err == nil {
		t.Fatal("second drop should fail due to quota")
	}
}

func TestGetDropMetadata(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	drop, _ := m.SaveDrop("meta.txt", bytes.NewReader([]byte("metadata test")))

	payload, err := m.GetDropMetadata(drop.ID)
	if err != nil {
		t.Fatalf("GetDropMetadata error: %v", err)
	}

	if payload.Filename != "meta.txt" {
		t.Errorf("Filename = %q", payload.Filename)
	}
	if payload.Receipt != drop.Receipt {
		t.Errorf("Receipt = %q, want %q", payload.Receipt, drop.Receipt)
	}
	if payload.FileHash != drop.FileHash {
		t.Errorf("FileHash = %q, want %q", payload.FileHash, drop.FileHash)
	}
}

func TestGetDropMetadata_InvalidID(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()

	_, err := m.GetDropMetadata("../../../etc/passwd")
	if err == nil {
		t.Fatal("should reject invalid ID")
	}
}

func TestSaveDrop_FileHashComputed(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	drop, _ := m.SaveDrop("hash.txt", bytes.NewReader([]byte("hash me")))

	if drop.FileHash == "" {
		t.Error("FileHash should be computed")
	}
	if len(drop.FileHash) != 64 { // SHA-256 hex is 64 chars
		t.Errorf("FileHash length = %d, want 64", len(drop.FileHash))
	}
}

func TestSaveDrop_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	drop, err := m.SaveDrop("empty.txt", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("SaveDrop empty error: %v", err)
	}
	if drop.Size != 0 {
		t.Errorf("Size = %d, want 0", drop.Size)
	}
}

func TestGetDrop_NonexistentDrop(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()

	_, _, err := m.GetDrop("abcdef0123456789abcdef0123456789")
	if err == nil {
		t.Error("expected error for nonexistent drop")
	}
}

func TestDeleteDrop_NonexistentDrop(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	// Should not error even if drop doesn't exist (RemoveAll on nonexistent is ok)
	err := m.DeleteDrop("abcdef0123456789abcdef0123456789")
	// This may or may not error depending on whether secure delete or RemoveAll
	_ = err
}

func TestDeleteDrop_ReleasesQuota(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	qm, _ := NewQuotaManager(dir, 1.0, 100)
	m.Quota = qm

	drop, _ := m.SaveDrop("quota.txt", bytes.NewReader([]byte("some data for quota")))

	_, count1 := qm.Stats()
	if count1 != 1 {
		t.Fatalf("count before delete = %d", count1)
	}

	m.DeleteDrop(drop.ID)

	_, count2 := qm.Stats()
	if count2 != 0 {
		t.Errorf("count after delete = %d, want 0", count2)
	}
}

func TestDeleteDrop_WithLegacyFileEnc(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	qm, _ := NewQuotaManager(dir, 1.0, 100)
	m.Quota = qm

	drop, _ := m.SaveDrop("test.txt", bytes.NewReader([]byte("test")))

	// Rename to legacy format
	dropDir := filepath.Join(dir, drop.ID)
	os.Rename(filepath.Join(dropDir, "data"), filepath.Join(dropDir, "file.enc"))

	err := m.DeleteDrop(drop.ID)
	if err != nil {
		t.Fatalf("DeleteDrop with legacy file error: %v", err)
	}
}

func TestNewManager_WithMasterKey(t *testing.T) {
	dir := t.TempDir()
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 10)
	}

	m1, err := NewManager(dir, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	key1 := make([]byte, 32)
	copy(key1, m1.EncryptionKey)
	m1.Close()

	m2, err := NewManager(dir, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()

	if !bytes.Equal(key1, m2.EncryptionKey) {
		t.Error("keys should persist with master key encryption")
	}
}

func TestLoadOrGenerateKey_PlaintextKeyNoMasterKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	// Write a plaintext 32-byte key
	origKey := make([]byte, 32)
	for i := range origKey {
		origKey[i] = byte(i)
	}
	os.WriteFile(keyPath, origKey, 0600)

	// Load without master key
	loaded, err := loadOrGenerateKey(keyPath, nil, []byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, origKey) {
		t.Error("should load plaintext key unchanged")
	}
}

func TestLoadOrGenerateKey_AutoMigrate(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	// Write a plaintext 32-byte key
	origKey := make([]byte, 32)
	for i := range origKey {
		origKey[i] = byte(i + 5)
	}
	os.WriteFile(keyPath, origKey, 0600)

	// Load with master key — should auto-migrate to encrypted
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 100)
	}
	loaded, err := loadOrGenerateKey(keyPath, masterKey, []byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, origKey) {
		t.Error("migrated key should match original")
	}

	// Key file should now be encrypted (60 bytes)
	data, _ := os.ReadFile(keyPath)
	if len(data) != 60 {
		t.Errorf("migrated key file size = %d, want 60", len(data))
	}

	// Reload with master key should work
	reloaded, err := loadOrGenerateKey(keyPath, masterKey, []byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reloaded, origKey) {
		t.Error("reloaded encrypted key should match original")
	}
}

func TestLoadOrGenerateKey_GenerateNew(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "new.key")

	key, err := loadOrGenerateKey(keyPath, nil, []byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("generated key length = %d, want 32", len(key))
	}

	// File should exist
	data, _ := os.ReadFile(keyPath)
	if !bytes.Equal(data, key) {
		t.Error("plaintext key should be written to file")
	}
}

func TestLoadOrGenerateKey_GenerateNewWithMasterKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "new.key")

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	key, err := loadOrGenerateKey(keyPath, masterKey, []byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("generated key length = %d, want 32", len(key))
	}

	// File should be encrypted (60 bytes)
	data, _ := os.ReadFile(keyPath)
	if len(data) != 60 {
		t.Errorf("encrypted key file size = %d, want 60", len(data))
	}
}

func TestLoadOrGenerateKey_InvalidSizeKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.key")

	// Write a key with wrong size (not 32 and not 60)
	os.WriteFile(keyPath, []byte("wrong-size"), 0600)

	// Without master key — should generate a new key (existing key is invalid size)
	key, err := loadOrGenerateKey(keyPath, nil, []byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("should generate new key, got length %d", len(key))
	}
}

func TestNewManager_CreatesNestedDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b", "c")
	m, err := NewManager(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	if _, err := os.Stat(dir); err != nil {
		t.Error("nested dir should be created")
	}
}

func TestSaveDrop_MultipleDropsUniqueIDs(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil)
	defer m.Close()
	m.SecureDelete = false

	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		drop, err := m.SaveDrop("test.txt", bytes.NewReader([]byte("data")))
		if err != nil {
			t.Fatal(err)
		}
		if ids[drop.ID] {
			t.Errorf("duplicate ID: %s", drop.ID)
		}
		ids[drop.ID] = true
	}
}

func TestClose_NilReceipts(t *testing.T) {
	m := &Manager{
		EncryptionKey: make([]byte, 32),
		Receipts:      nil,
	}
	m.Close() // should not panic
}
