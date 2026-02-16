package honeypot

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/scttfrdmn/dead-drop/internal/storage"
)

// Manager tracks honeypot drop IDs and fires alerts on access.
type Manager struct {
	mu         sync.RWMutex
	ids        map[string]bool
	storageDir string
	listPath   string
	alerter    *Alerter
}

// NewManager creates a honeypot manager, loading any existing honeypot IDs
// from the .honeypots file in storageDir.
func NewManager(storageDir, webhookURL string) (*Manager, error) {
	m := &Manager{
		ids:        make(map[string]bool),
		storageDir: storageDir,
		listPath:   filepath.Join(storageDir, ".honeypots"),
	}

	if webhookURL != "" {
		m.alerter = NewAlerter(webhookURL)
	}

	// Load existing honeypot IDs
	data, err := os.ReadFile(m.listPath) // #nosec G304 -- internal path
	if err == nil {
		var ids []string
		if jsonErr := json.Unmarshal(data, &ids); jsonErr != nil {
			return nil, fmt.Errorf("failed to parse .honeypots file: %w", jsonErr)
		}
		for _, id := range ids {
			m.ids[id] = true
		}
	}

	return m, nil
}

// IsHoneypot returns true if the given drop ID is a honeypot.
func (m *Manager) IsHoneypot(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ids[id]
}

// GenerateHoneypots creates count canary drops using the storage manager.
// Idempotent: if honeypots already exist, no new ones are created.
func (m *Manager) GenerateHoneypots(count int, sm *storage.Manager) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.ids) > 0 {
		return nil // already generated
	}

	for i := 0; i < count; i++ {
		// Random decoy content: 1-10 KB
		sizeBig, err := rand.Int(rand.Reader, big.NewInt(9*1024))
		if err != nil {
			return fmt.Errorf("failed to generate random size: %w", err)
		}
		size := int(sizeBig.Int64()) + 1024

		buf := make([]byte, size)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("failed to generate decoy data: %w", err)
		}

		drop, err := sm.SaveDrop("document.bin", bytes.NewReader(buf))
		if err != nil {
			return fmt.Errorf("failed to save honeypot drop: %w", err)
		}

		m.ids[drop.ID] = true
	}

	// Persist IDs
	if err := m.saveIDs(); err != nil {
		return err
	}

	log.Printf("Generated %d honeypot drops", count)
	return nil
}

// Alert logs and optionally sends a webhook alert for a honeypot access.
func (m *Manager) Alert(dropID, remoteAddr string) {
	log.Printf("HONEYPOT ALERT: drop %s accessed from %s", dropID, remoteAddr)

	if m.alerter != nil {
		m.alerter.Send(&AlertPayload{
			Event:      "honeypot_access",
			DropID:     dropID,
			RemoteAddr: remoteAddr,
		})
	}
}

// IDs returns the list of honeypot drop IDs.
func (m *Manager) IDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.ids))
	for id := range m.ids {
		ids = append(ids, id)
	}
	return ids
}

func (m *Manager) saveIDs() error {
	ids := make([]string, 0, len(m.ids))
	for id := range m.ids {
		ids = append(ids, id)
	}

	data, err := json.Marshal(ids)
	if err != nil {
		return fmt.Errorf("failed to marshal honeypot IDs: %w", err)
	}

	if err := os.WriteFile(m.listPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write .honeypots file: %w", err)
	}

	return nil
}
