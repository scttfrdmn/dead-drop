package storage

import (
	"crypto/rand"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)

// CleanupConfig holds cleanup settings
type CleanupConfig struct {
	MaxAge           time.Duration
	CheckInterval    time.Duration
	DeleteOnRetrieve bool
}

// StartCleanup begins periodic cleanup of expired drops with random jitter
// to prevent timing analysis. Each cycle sleeps for the check interval
// plus a random jitter of +/- 10 minutes.
func (m *Manager) StartCleanup(config CleanupConfig) {
	go func() {
		for {
			sleep := config.CheckInterval + cleanupJitter()
			time.Sleep(sleep)
			if err := m.cleanupExpiredDrops(config.MaxAge); err != nil {
				log.Printf("Cleanup error: %v", err)
			}
		}
	}()
}

// cleanupJitter returns a random duration between -10 and +10 minutes.
func cleanupJitter() time.Duration {
	// Generate 0..20 minutes, then subtract 10 to get -10..+10
	n, err := rand.Int(rand.Reader, big.NewInt(20*60))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64()-10*60) * time.Second
}

// cleanupExpiredDrops removes drops older than maxAge
func (m *Manager) cleanupExpiredDrops(maxAge time.Duration) error {
	entries, err := os.ReadDir(m.StorageDir)
	if err != nil {
		return err
	}

	now := time.Now()
	deletedCount := 0

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		dropID := entry.Name()

		// Skip protected drops (e.g., honeypots)
		if m.IsProtected != nil && m.IsProtected(dropID) {
			continue
		}

		// Skip drops that are currently locked (being retrieved)
		if !m.Locks.TryLock(dropID) {
			continue
		}
		// We got the write lock — release it since DeleteDrop will acquire it
		m.Locks.Unlock(dropID)

		// Load encrypted metadata to get timestamp
		payload, err := m.GetDropMetadata(dropID)
		if err != nil {
			continue
		}

		dropTime := time.Unix(payload.TimestampHour, 0)
		if now.Sub(dropTime) > maxAge {
			if err := m.DeleteDrop(dropID); err != nil {
				log.Printf("Failed to delete expired drop %s: %v", dropID, err)
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		log.Printf("Cleaned up %d expired drops", deletedCount)
	}

	return nil
}

// GetDropAge returns the age of a drop
func (m *Manager) GetDropAge(id string) (time.Duration, error) {
	payload, err := m.GetDropMetadata(id)
	if err != nil {
		return 0, err
	}

	if payload.TimestampHour == 0 {
		return 0, nil
	}

	dropTime := time.Unix(payload.TimestampHour, 0)
	return time.Since(dropTime), nil
}
