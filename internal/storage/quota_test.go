package storage

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestNewQuotaManager_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	qm, err := NewQuotaManager(dir, 1.0, 100)
	if err != nil {
		t.Fatalf("NewQuotaManager error: %v", err)
	}

	totalBytes, dropCount := qm.Stats()
	if totalBytes != 0 {
		t.Errorf("totalBytes = %d, want 0", totalBytes)
	}
	if dropCount != 0 {
		t.Errorf("dropCount = %d, want 0", dropCount)
	}
}

func TestNewQuotaManager_ScansExistingDrops(t *testing.T) {
	dir := t.TempDir()

	// Create a drop with "data" file
	drop1 := filepath.Join(dir, "abcdef0123456789abcdef0123456789")
	os.MkdirAll(drop1, 0700)
	os.WriteFile(filepath.Join(drop1, "data"), make([]byte, 1000), 0600)

	// Create a drop with legacy "file.enc"
	drop2 := filepath.Join(dir, "1234567890abcdef1234567890abcdef")
	os.MkdirAll(drop2, 0700)
	os.WriteFile(filepath.Join(drop2, "file.enc"), make([]byte, 2000), 0600)

	qm, err := NewQuotaManager(dir, 1.0, 100)
	if err != nil {
		t.Fatal(err)
	}

	totalBytes, dropCount := qm.Stats()
	if totalBytes != 3000 {
		t.Errorf("totalBytes = %d, want 3000", totalBytes)
	}
	if dropCount != 2 {
		t.Errorf("dropCount = %d, want 2", dropCount)
	}
}

func TestNewQuotaManager_SkipsDotFiles(t *testing.T) {
	dir := t.TempDir()

	// Hidden dir should be skipped
	os.MkdirAll(filepath.Join(dir, ".hidden"), 0700)
	os.WriteFile(filepath.Join(dir, ".hidden", "data"), make([]byte, 500), 0600)

	// Regular file (not a dir) should be skipped
	os.WriteFile(filepath.Join(dir, "somefile"), make([]byte, 100), 0600)

	qm, err := NewQuotaManager(dir, 1.0, 100)
	if err != nil {
		t.Fatal(err)
	}

	_, dropCount := qm.Stats()
	if dropCount != 0 {
		t.Errorf("dropCount = %d, want 0", dropCount)
	}
}

func TestQuotaManager_Reserve_UnderLimit(t *testing.T) {
	dir := t.TempDir()
	qm, _ := NewQuotaManager(dir, 1.0, 10) // 1GB, 10 drops

	if err := qm.Reserve(1024); err != nil {
		t.Errorf("Reserve should succeed: %v", err)
	}

	totalBytes, dropCount := qm.Stats()
	if totalBytes != 1024 {
		t.Errorf("totalBytes = %d, want 1024", totalBytes)
	}
	if dropCount != 1 {
		t.Errorf("dropCount = %d, want 1", dropCount)
	}
}

func TestQuotaManager_Reserve_ByteQuotaExceeded(t *testing.T) {
	dir := t.TempDir()
	qm, _ := NewQuotaManager(dir, 0.001, 100) // ~1MB

	// Reserve more than the ~1MB limit
	if err := qm.Reserve(2 * 1024 * 1024); err == nil {
		t.Fatal("Reserve should fail when byte quota exceeded")
	}
}

func TestQuotaManager_Reserve_DropCountExceeded(t *testing.T) {
	dir := t.TempDir()
	qm, _ := NewQuotaManager(dir, 10.0, 2) // max 2 drops

	qm.Reserve(100)
	qm.Reserve(100)

	if err := qm.Reserve(100); err == nil {
		t.Fatal("Reserve should fail when drop count exceeded")
	}
}

func TestQuotaManager_Reserve_UnlimitedWhenZero(t *testing.T) {
	dir := t.TempDir()
	qm, _ := NewQuotaManager(dir, 0, 0) // unlimited

	for i := 0; i < 100; i++ {
		if err := qm.Reserve(1024 * 1024); err != nil {
			t.Fatalf("unlimited quota should not fail: %v", err)
		}
	}
}

func TestQuotaManager_Release(t *testing.T) {
	dir := t.TempDir()
	qm, _ := NewQuotaManager(dir, 1.0, 10)

	qm.Reserve(1000)
	qm.Release(1000)

	totalBytes, dropCount := qm.Stats()
	if totalBytes != 0 {
		t.Errorf("totalBytes = %d, want 0", totalBytes)
	}
	if dropCount != 0 {
		t.Errorf("dropCount = %d, want 0", dropCount)
	}
}

func TestQuotaManager_Release_UnderflowProtection(t *testing.T) {
	dir := t.TempDir()
	qm, _ := NewQuotaManager(dir, 1.0, 10)

	// Release without prior reserve — should clamp to 0
	qm.Release(5000)

	totalBytes, dropCount := qm.Stats()
	if totalBytes != 0 {
		t.Errorf("totalBytes = %d, want 0 (underflow protection)", totalBytes)
	}
	if dropCount != 0 {
		t.Errorf("dropCount = %d, want 0 (underflow protection)", dropCount)
	}
}

func TestQuotaManager_ThreadSafe(t *testing.T) {
	dir := t.TempDir()
	qm, _ := NewQuotaManager(dir, 0, 0) // unlimited

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			qm.Reserve(100)
			qm.Stats()
			qm.Release(50)
		}()
	}
	wg.Wait()

	totalBytes, dropCount := qm.Stats()
	// 100 reserves of 100 - 100 releases of 50 = 5000 bytes, 0 drops (100 - 100)
	if totalBytes != 5000 {
		t.Errorf("totalBytes = %d, want 5000", totalBytes)
	}
	if dropCount != 0 {
		t.Errorf("dropCount = %d, want 0", dropCount)
	}
}
