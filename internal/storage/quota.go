package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// QuotaManager tracks total storage usage and drop count.
type QuotaManager struct {
	mu         sync.Mutex
	totalBytes int64
	dropCount  int
	maxBytes   int64
	maxDrops   int
}

// NewQuotaManager creates a quota manager and scans existing drops.
func NewQuotaManager(storageDir string, maxGB float64, maxDrops int) (*QuotaManager, error) {
	qm := &QuotaManager{
		maxBytes: int64(maxGB * 1024 * 1024 * 1024),
		maxDrops: maxDrops,
	}

	// Scan existing drops to initialize counters
	entries, err := os.ReadDir(storageDir)
	if err != nil {
		return nil, fmt.Errorf("failed to scan storage: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		filePath := filepath.Join(storageDir, entry.Name(), "file.enc")
		if info, err := os.Stat(filePath); err == nil {
			qm.totalBytes += info.Size()
			qm.dropCount++
		}
	}

	return qm, nil
}

// Reserve attempts to reserve space for a new drop.
func (qm *QuotaManager) Reserve(bytes int64) error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	if qm.maxBytes > 0 && qm.totalBytes+bytes > qm.maxBytes {
		return fmt.Errorf("storage quota exceeded (%.1f GB used of %.1f GB)",
			float64(qm.totalBytes)/(1024*1024*1024),
			float64(qm.maxBytes)/(1024*1024*1024))
	}

	if qm.maxDrops > 0 && qm.dropCount+1 > qm.maxDrops {
		return fmt.Errorf("drop count quota exceeded (%d of %d)", qm.dropCount, qm.maxDrops)
	}

	qm.totalBytes += bytes
	qm.dropCount++
	return nil
}

// Release frees reserved space when a drop is deleted.
func (qm *QuotaManager) Release(bytes int64) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	qm.totalBytes -= bytes
	if qm.totalBytes < 0 {
		qm.totalBytes = 0
	}
	qm.dropCount--
	if qm.dropCount < 0 {
		qm.dropCount = 0
	}
}
