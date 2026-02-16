package honeypot

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/dead-drop/internal/storage"
)

func setupTestStorage(t *testing.T) (*storage.Manager, string) {
	t.Helper()
	dir := t.TempDir()
	sm, err := storage.NewManager(dir, nil)
	if err != nil {
		t.Fatalf("failed to create storage manager: %v", err)
	}
	t.Cleanup(func() { sm.Close() })
	return sm, dir
}

func TestNewManager(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, "")
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if len(m.ids) != 0 {
		t.Errorf("expected empty ID set, got %d", len(m.ids))
	}

	if m.alerter != nil {
		t.Error("expected nil alerter when no webhook URL")
	}
}

func TestNewManagerWithWebhook(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, "http://example.com/hook")
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if m.alerter == nil {
		t.Error("expected alerter when webhook URL is provided")
	}
}

func TestGenerateHoneypots(t *testing.T) {
	sm, dir := setupTestStorage(t)
	m, err := NewManager(dir, "")
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	count := 5
	if err := m.GenerateHoneypots(count, sm); err != nil {
		t.Fatalf("GenerateHoneypots failed: %v", err)
	}

	// Verify correct number
	ids := m.IDs()
	if len(ids) != count {
		t.Errorf("expected %d honeypots, got %d", count, len(ids))
	}

	// Verify IsHoneypot
	for _, id := range ids {
		if !m.IsHoneypot(id) {
			t.Errorf("expected IsHoneypot(%s) = true", id)
		}
	}

	// Verify .honeypots file exists
	listPath := filepath.Join(dir, ".honeypots")
	data, err := os.ReadFile(listPath)
	if err != nil {
		t.Fatalf("failed to read .honeypots: %v", err)
	}

	var saved []string
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("failed to parse .honeypots: %v", err)
	}
	if len(saved) != count {
		t.Errorf("expected %d saved IDs, got %d", count, len(saved))
	}
}

func TestIdempotent(t *testing.T) {
	sm, dir := setupTestStorage(t)
	m, err := NewManager(dir, "")
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if err := m.GenerateHoneypots(3, sm); err != nil {
		t.Fatalf("first GenerateHoneypots failed: %v", err)
	}
	firstIDs := m.IDs()

	// Second call should be a no-op
	if err := m.GenerateHoneypots(3, sm); err != nil {
		t.Fatalf("second GenerateHoneypots failed: %v", err)
	}
	secondIDs := m.IDs()

	if len(firstIDs) != len(secondIDs) {
		t.Errorf("idempotency failed: first=%d second=%d", len(firstIDs), len(secondIDs))
	}
}

func TestPersistence(t *testing.T) {
	sm, dir := setupTestStorage(t)
	m, err := NewManager(dir, "")
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if err := m.GenerateHoneypots(3, sm); err != nil {
		t.Fatalf("GenerateHoneypots failed: %v", err)
	}
	originalIDs := m.IDs()

	// Create a new manager from the same dir — should load persisted IDs
	m2, err := NewManager(dir, "")
	if err != nil {
		t.Fatalf("NewManager (reload) failed: %v", err)
	}

	for _, id := range originalIDs {
		if !m2.IsHoneypot(id) {
			t.Errorf("reloaded manager missing honeypot %s", id)
		}
	}

	// Idempotent after reload
	if err := m2.GenerateHoneypots(3, sm); err != nil {
		t.Fatalf("GenerateHoneypots after reload failed: %v", err)
	}
	if len(m2.IDs()) != len(originalIDs) {
		t.Errorf("expected same count after reload, got %d vs %d", len(m2.IDs()), len(originalIDs))
	}
}

func TestAlert(t *testing.T) {
	var mu sync.Mutex
	var received *AlertPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p AlertPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("failed to decode webhook payload: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = &p
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m, err := NewManager(dir, srv.URL)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	m.Alert("abc123", "192.168.1.1")

	// Wait for async webhook
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		got := received
		mu.Unlock()
		if got != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for webhook")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if received.Event != "honeypot_access" {
		t.Errorf("expected event 'honeypot_access', got %q", received.Event)
	}
	if received.DropID != "abc123" {
		t.Errorf("expected drop_id 'abc123', got %q", received.DropID)
	}
	if received.RemoteAddr != "192.168.1.1" {
		t.Errorf("expected remote_addr '192.168.1.1', got %q", received.RemoteAddr)
	}
	if received.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestIsHoneypotNotFound(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, "")
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if m.IsHoneypot("nonexistent") {
		t.Error("expected IsHoneypot to return false for unknown ID")
	}
}
