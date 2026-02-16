package storage

import (
	"sync"
	"testing"
	"time"
)

func TestDropLockManager_RLock_RUnlock(t *testing.T) {
	lm := NewDropLockManager()
	lm.RLock("drop1")
	lm.RUnlock("drop1")
	// Should not panic or deadlock
}

func TestDropLockManager_Lock_Unlock(t *testing.T) {
	lm := NewDropLockManager()
	lm.Lock("drop1")
	lm.Unlock("drop1")
}

func TestDropLockManager_UnlockCleansUp(t *testing.T) {
	lm := NewDropLockManager()
	lm.Lock("drop1")
	lm.Unlock("drop1")

	// After Unlock, the lock entry should be removed
	lm.mu.Lock()
	_, exists := lm.locks["drop1"]
	lm.mu.Unlock()

	if exists {
		t.Error("lock entry should be cleaned up after Unlock")
	}
}

func TestDropLockManager_TryLock_Free(t *testing.T) {
	lm := NewDropLockManager()
	if !lm.TryLock("drop1") {
		t.Error("TryLock should succeed when lock is free")
	}
	lm.Unlock("drop1")
}

func TestDropLockManager_TryLock_Held(t *testing.T) {
	lm := NewDropLockManager()
	lm.Lock("drop1")

	if lm.TryLock("drop1") {
		t.Error("TryLock should fail when write lock is held")
	}

	lm.Unlock("drop1")
}

func TestDropLockManager_ConcurrentReaders(t *testing.T) {
	lm := NewDropLockManager()
	var wg sync.WaitGroup
	const readers = 10

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lm.RLock("drop1")
			time.Sleep(10 * time.Millisecond)
			lm.RUnlock("drop1")
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent readers deadlocked")
	}
}

func TestDropLockManager_WriterBlocksReaders(t *testing.T) {
	lm := NewDropLockManager()

	// Get the underlying lock directly to avoid Unlock's cleanup
	lock := lm.getLock("drop1")
	lock.Lock() // acquire write lock

	blocked := make(chan struct{})
	go func() {
		lock.RLock() // should block until writer releases
		close(blocked)
		lock.RUnlock()
	}()

	select {
	case <-blocked:
		t.Fatal("reader should be blocked while writer holds lock")
	case <-time.After(50 * time.Millisecond):
		// good, reader is blocked
	}

	lock.Unlock() // release write lock

	select {
	case <-blocked:
		// good, reader unblocked
	case <-time.After(time.Second):
		t.Fatal("reader should unblock after writer releases")
	}
}

func TestDropLockManager_IndependentDrops(t *testing.T) {
	lm := NewDropLockManager()
	lm.Lock("drop1")

	// drop2 should be independently lockable
	if !lm.TryLock("drop2") {
		t.Error("different drop should be independently lockable")
	}
	lm.Unlock("drop2")
	lm.Unlock("drop1")
}
