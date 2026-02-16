package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	m, err := NewManager(dir, nil)
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	m.SecureDelete = false // faster for tests
	return m
}

func TestCleanupExpiredDrops_DeletesExpired(t *testing.T) {
	m := setupTestManager(t)
	defer m.Close()

	drop, err := m.SaveDrop("old.txt", bytes.NewReader([]byte("old data")))
	if err != nil {
		t.Fatal(err)
	}

	// Manually set timestamp to 2 hours ago
	metaPath := filepath.Join(m.StorageDir, drop.ID, "meta")
	payload := &MetadataPayload{
		Filename:      "old.txt",
		Receipt:       drop.Receipt,
		TimestampHour: time.Now().Add(-2 * time.Hour).Truncate(time.Hour).Unix(),
	}
	if err := saveEncryptedMetadata(metaPath, m.EncryptionKey, drop.ID, payload); err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupExpiredDrops(1 * time.Hour); err != nil {
		t.Fatal(err)
	}

	_, _, err = m.GetDrop(drop.ID)
	if err == nil {
		t.Error("expired drop should be deleted")
	}
}

func TestCleanupExpiredDrops_PreservesRecent(t *testing.T) {
	m := setupTestManager(t)
	defer m.Close()

	drop, err := m.SaveDrop("recent.txt", bytes.NewReader([]byte("recent data")))
	if err != nil {
		t.Fatal(err)
	}

	if err := m.cleanupExpiredDrops(24 * time.Hour); err != nil {
		t.Fatal(err)
	}

	_, reader, err := m.GetDrop(drop.ID)
	if err != nil {
		t.Errorf("recent drop should be preserved: %v", err)
	}
	if reader != nil {
		reader.Close()
	}
}

func TestCleanupExpiredDrops_SkipsProtected(t *testing.T) {
	m := setupTestManager(t)
	defer m.Close()

	drop, err := m.SaveDrop("honeypot.txt", bytes.NewReader([]byte("honeypot data")))
	if err != nil {
		t.Fatal(err)
	}

	m.IsProtected = func(id string) bool {
		return id == drop.ID
	}

	metaPath := filepath.Join(m.StorageDir, drop.ID, "meta")
	payload := &MetadataPayload{
		Filename:      "honeypot.txt",
		Receipt:       drop.Receipt,
		TimestampHour: time.Now().Add(-100 * time.Hour).Truncate(time.Hour).Unix(),
	}
	saveEncryptedMetadata(metaPath, m.EncryptionKey, drop.ID, payload)

	if err := m.cleanupExpiredDrops(1 * time.Hour); err != nil {
		t.Fatal(err)
	}

	_, reader, err := m.GetDrop(drop.ID)
	if err != nil {
		t.Errorf("protected drop should be preserved: %v", err)
	}
	if reader != nil {
		reader.Close()
	}
}

func TestCleanupExpiredDrops_SkipsLockedDrops(t *testing.T) {
	m := setupTestManager(t)
	defer m.Close()

	drop, err := m.SaveDrop("locked.txt", bytes.NewReader([]byte("locked data")))
	if err != nil {
		t.Fatal(err)
	}

	metaPath := filepath.Join(m.StorageDir, drop.ID, "meta")
	payload := &MetadataPayload{
		Filename:      "locked.txt",
		Receipt:       drop.Receipt,
		TimestampHour: time.Now().Add(-100 * time.Hour).Truncate(time.Hour).Unix(),
	}
	saveEncryptedMetadata(metaPath, m.EncryptionKey, drop.ID, payload)

	// Hold write lock
	m.Locks.Lock(drop.ID)

	if err := m.cleanupExpiredDrops(1 * time.Hour); err != nil {
		t.Fatal(err)
	}

	m.Locks.Unlock(drop.ID)

	dropDir := filepath.Join(m.StorageDir, drop.ID)
	if _, err := os.Stat(dropDir); os.IsNotExist(err) {
		t.Error("locked drop should be skipped during cleanup")
	}
}

func TestGetDropAge(t *testing.T) {
	m := setupTestManager(t)
	defer m.Close()

	drop, err := m.SaveDrop("test.txt", bytes.NewReader([]byte("test")))
	if err != nil {
		t.Fatal(err)
	}

	age, err := m.GetDropAge(drop.ID)
	if err != nil {
		t.Fatal(err)
	}

	if age > 2*time.Hour {
		t.Errorf("age = %v, expected within 2 hours", age)
	}
}

func TestGetDropAge_InvalidID(t *testing.T) {
	m := setupTestManager(t)
	defer m.Close()

	_, err := m.GetDropAge("invalid")
	if err == nil {
		t.Error("expected error for invalid ID")
	}
}

func TestGetDropAge_ZeroTimestamp(t *testing.T) {
	m := setupTestManager(t)
	defer m.Close()

	drop, _ := m.SaveDrop("test.txt", bytes.NewReader([]byte("test")))

	// Overwrite metadata with zero timestamp
	metaPath := filepath.Join(m.StorageDir, drop.ID, "meta")
	payload := &MetadataPayload{
		Filename:      "test.txt",
		Receipt:       drop.Receipt,
		TimestampHour: 0,
	}
	saveEncryptedMetadata(metaPath, m.EncryptionKey, drop.ID, payload)

	age, err := m.GetDropAge(drop.ID)
	if err != nil {
		t.Fatal(err)
	}
	if age != 0 {
		t.Errorf("age = %v, want 0 for zero timestamp", age)
	}
}

func TestCleanupExpiredDrops_SkipsDotDirsAndFiles(t *testing.T) {
	m := setupTestManager(t)
	defer m.Close()

	// Create a hidden directory and a regular file — both should be skipped
	os.MkdirAll(filepath.Join(m.StorageDir, ".hidden"), 0700)
	os.WriteFile(filepath.Join(m.StorageDir, "somefile"), []byte("data"), 0600)

	err := m.cleanupExpiredDrops(1 * time.Hour)
	if err != nil {
		t.Fatalf("cleanup with non-drop entries should not error: %v", err)
	}
}

func TestCleanupExpiredDrops_SkipsDropsWithBadMetadata(t *testing.T) {
	m := setupTestManager(t)
	defer m.Close()

	// Create a drop directory without metadata file
	dropID := "abcdef0123456789abcdef0123456789"
	dropDir := filepath.Join(m.StorageDir, dropID)
	os.MkdirAll(dropDir, 0700)

	// Should skip drops with unreadable metadata
	err := m.cleanupExpiredDrops(1 * time.Hour)
	if err != nil {
		t.Fatalf("cleanup should skip drops with bad metadata: %v", err)
	}
}

func TestCleanupJitter(t *testing.T) {
	for i := 0; i < 100; i++ {
		j := cleanupJitter()
		if j < -10*time.Minute || j > 10*time.Minute {
			t.Errorf("jitter %v out of range [-10min, +10min]", j)
		}
	}
}
