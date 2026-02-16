package storage

import (
	"sync"
)

// DropLockManager provides per-drop read/write locking to prevent
// race conditions between retrieval and cleanup/deletion.
type DropLockManager struct {
	mu    sync.Mutex
	locks map[string]*sync.RWMutex
}

// NewDropLockManager creates a new lock manager.
func NewDropLockManager() *DropLockManager {
	return &DropLockManager{
		locks: make(map[string]*sync.RWMutex),
	}
}

func (lm *DropLockManager) getLock(dropID string) *sync.RWMutex {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lock, ok := lm.locks[dropID]
	if !ok {
		lock = &sync.RWMutex{}
		lm.locks[dropID] = lock
	}
	return lock
}

// RLock acquires a read lock for the given drop.
func (lm *DropLockManager) RLock(dropID string) {
	lm.getLock(dropID).RLock()
}

// RUnlock releases the read lock for the given drop.
func (lm *DropLockManager) RUnlock(dropID string) {
	lm.getLock(dropID).RUnlock()
}

// Lock acquires a write lock for the given drop.
func (lm *DropLockManager) Lock(dropID string) {
	lm.getLock(dropID).Lock()
}

// Unlock releases the write lock and cleans up the lock entry.
func (lm *DropLockManager) Unlock(dropID string) {
	lm.getLock(dropID).Unlock()

	// Clean up the lock entry after write unlock (drop is being deleted)
	lm.mu.Lock()
	delete(lm.locks, dropID)
	lm.mu.Unlock()
}

// TryLock attempts to acquire a write lock without blocking.
// Returns true if the lock was acquired.
func (lm *DropLockManager) TryLock(dropID string) bool {
	return lm.getLock(dropID).TryLock()
}
