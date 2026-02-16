package storage

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/scttfrdmn/dead-drop/internal/crypto"
)

// Drop represents a submitted file
type Drop struct {
	ID        string
	Filename  string
	Size      int64
	Timestamp time.Time
	Receipt   string
	FileHash  string
}

// Manager handles file storage operations
type Manager struct {
	StorageDir    string
	EncryptionKey []byte
	Receipts      *ReceiptManager
	Quota         *QuotaManager
	Locks         *DropLockManager
	SecureDelete  bool
}

// NewManager creates a new storage manager
func NewManager(storageDir string) (*Manager, error) {
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Load or generate encryption key
	keyPath := filepath.Join(storageDir, ".encryption.key")
	key, err := loadOrGenerateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load encryption key: %w", err)
	}

	// Initialize receipt manager
	receiptKeyPath := filepath.Join(storageDir, ".receipt.key")
	receipts, err := NewReceiptManager(receiptKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize receipt manager: %w", err)
	}

	return &Manager{
		StorageDir:    storageDir,
		EncryptionKey: key,
		Receipts:      receipts,
		Locks:         NewDropLockManager(),
		SecureDelete:  true,
	}, nil
}

// Close zeros sensitive key material.
func (m *Manager) Close() {
	ZeroBytes(m.EncryptionKey)
	if m.Receipts != nil {
		ZeroBytes(m.Receipts.secret)
	}
}

// loadOrGenerateKey loads existing key or generates new one
func loadOrGenerateKey(keyPath string) ([]byte, error) {
	// Try to load existing key
	if data, err := os.ReadFile(keyPath); err == nil {
		if len(data) == 32 {
			return data, nil
		}
	}

	// Generate new key
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Save key with restricted permissions
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	return key, nil
}

// generateID creates a random hex ID
func generateID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// SaveDrop stores an uploaded file with encryption
func (m *Manager) SaveDrop(filename string, reader io.Reader) (*Drop, error) {
	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ID: %w", err)
	}

	// Generate HMAC receipt
	receipt := m.Receipts.Generate(id)

	// Create drop directory
	dropDir := filepath.Join(m.StorageDir, id)
	if err := os.MkdirAll(dropDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create drop directory: %w", err)
	}

	// Read file data for size calculation and hashing
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	defer ZeroBytes(data)

	size := int64(len(data))

	// Check quota if configured
	if m.Quota != nil {
		if err := m.Quota.Reserve(size); err != nil {
			os.Remove(dropDir)
			return nil, fmt.Errorf("quota exceeded: %w", err)
		}
	}

	// Compute file hash
	fileHash := computeSHA256(data)

	// Encrypt and save file with AAD
	filePath := filepath.Join(dropDir, "file.enc")
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if err := crypto.EncryptStream(m.EncryptionKey, bytes.NewReader(data), f, []byte(id)); err != nil {
		return nil, fmt.Errorf("failed to encrypt file: %w", err)
	}

	// Save encrypted metadata with timestamp rounded to hour
	now := roundToHour(time.Now())
	metaPayload := &MetadataPayload{
		Filename:      filename,
		Receipt:       receipt,
		TimestampHour: now.Unix(),
		FileHash:      fileHash,
	}

	metaPath := filepath.Join(dropDir, "meta")
	if err := saveEncryptedMetadata(metaPath, m.EncryptionKey, id, metaPayload); err != nil {
		return nil, fmt.Errorf("failed to save metadata: %w", err)
	}

	return &Drop{
		ID:        id,
		Filename:  filename,
		Size:      size,
		Timestamp: now,
		Receipt:   receipt,
		FileHash:  fileHash,
	}, nil
}

// GetDrop retrieves and decrypts a drop by ID
func (m *Manager) GetDrop(id string) (string, io.ReadCloser, error) {
	// SECURITY: Validate drop ID to prevent path traversal
	if err := ValidateDropID(id); err != nil {
		return "", nil, fmt.Errorf("invalid drop ID: %w", err)
	}

	// Acquire read lock
	m.Locks.RLock(id)
	defer m.Locks.RUnlock(id)

	dropDir := filepath.Join(m.StorageDir, id)

	// Read encrypted metadata
	metaPath := filepath.Join(dropDir, "meta")
	payload, err := loadEncryptedMetadata(metaPath, m.EncryptionKey, id)
	if err != nil {
		return "", nil, fmt.Errorf("drop not found: %w", err)
	}

	// Open encrypted file
	filePath := filepath.Join(dropDir, "file.enc")
	f, err := os.Open(filePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Decrypt with AAD
	decrypted := bytes.NewBuffer(nil)
	if err := crypto.DecryptStream(m.EncryptionKey, f, decrypted, []byte(id)); err != nil {
		return "", nil, fmt.Errorf("failed to decrypt file: %w", err)
	}

	return payload.Filename, io.NopCloser(decrypted), nil
}

// GetDropMetadata retrieves the metadata for a drop without decrypting the file.
func (m *Manager) GetDropMetadata(id string) (*MetadataPayload, error) {
	if err := ValidateDropID(id); err != nil {
		return nil, fmt.Errorf("invalid drop ID: %w", err)
	}

	metaPath := filepath.Join(m.StorageDir, id, "meta")
	return loadEncryptedMetadata(metaPath, m.EncryptionKey, id)
}

// DeleteDrop removes a drop
func (m *Manager) DeleteDrop(id string) error {
	// SECURITY: Validate drop ID to prevent path traversal
	if err := ValidateDropID(id); err != nil {
		return fmt.Errorf("invalid drop ID: %w", err)
	}

	// Acquire write lock
	m.Locks.Lock(id)
	defer m.Locks.Unlock(id)

	dropDir := filepath.Join(m.StorageDir, id)

	// Release quota for the encrypted file size
	if m.Quota != nil {
		filePath := filepath.Join(dropDir, "file.enc")
		if info, err := os.Stat(filePath); err == nil {
			m.Quota.Release(info.Size())
		}
	}

	if m.SecureDelete {
		return SecureDeleteDir(dropDir)
	}
	return os.RemoveAll(dropDir)
}
