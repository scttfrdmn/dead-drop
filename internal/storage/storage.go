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
	IsProtected   func(id string) bool
}

// NewManager creates a new storage manager.
// If masterKey is non-nil, key files are encrypted at rest using the master key.
func NewManager(storageDir string, masterKey []byte) (*Manager, error) {
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Load or generate encryption key
	keyPath := filepath.Join(storageDir, ".encryption.key")
	key, err := loadOrGenerateKey(keyPath, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load encryption key: %w", err)
	}

	// Initialize receipt manager
	receiptKeyPath := filepath.Join(storageDir, ".receipt.key")
	receipts, err := NewReceiptManager(receiptKeyPath, masterKey)
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

// loadOrGenerateKey loads existing key or generates new one.
// If masterKey is non-nil, the key file is encrypted at rest.
// Plaintext key files (32 bytes) are auto-migrated to encrypted (60 bytes) when a master key is provided.
func loadOrGenerateKey(keyPath string, masterKey []byte) ([]byte, error) {
	data, err := os.ReadFile(keyPath) // #nosec G304 -- keyPath is internal, not user-controlled
	if err == nil {
		if masterKey == nil {
			// No master key: expect plaintext 32-byte key
			if len(data) == 32 {
				return data, nil
			}
		} else if len(data) == crypto.EncryptedKeySize {
			// Master key provided + encrypted key file: decrypt
			return crypto.DecryptKeyFile(masterKey, data)
		} else if len(data) == 32 {
			// Master key provided + plaintext key file: auto-migrate
			encrypted, encErr := crypto.EncryptKeyFile(masterKey, data)
			if encErr != nil {
				return nil, fmt.Errorf("failed to encrypt key during migration: %w", encErr)
			}
			if writeErr := os.WriteFile(keyPath, encrypted, 0600); writeErr != nil {
				return nil, fmt.Errorf("failed to write encrypted key: %w", writeErr)
			}
			return data, nil
		}
	}

	// Generate new key
	key, genErr := crypto.GenerateKey()
	if genErr != nil {
		return nil, fmt.Errorf("failed to generate key: %w", genErr)
	}

	// Save key (encrypted if master key is set)
	toWrite := key
	if masterKey != nil {
		encrypted, encErr := crypto.EncryptKeyFile(masterKey, key)
		if encErr != nil {
			return nil, fmt.Errorf("failed to encrypt new key: %w", encErr)
		}
		toWrite = encrypted
	}

	if writeErr := os.WriteFile(keyPath, toWrite, 0600); writeErr != nil {
		return nil, fmt.Errorf("failed to save key: %w", writeErr)
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
			_ = os.Remove(dropDir)
			return nil, fmt.Errorf("quota exceeded: %w", err)
		}
	}

	// Compute file hash
	fileHash := computeSHA256(data)

	// Encrypt and save file with AAD
	filePath := filepath.Join(dropDir, "data")
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 -- path built from validated drop ID
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

	// Open encrypted file (try "data" first, fall back to legacy "file.enc")
	filePath := filepath.Join(dropDir, "data")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		filePath = filepath.Join(dropDir, "file.enc")
	}
	f, err := os.Open(filePath) // #nosec G304 -- path built from validated drop ID
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

// deleteIfExpired atomically checks whether a drop is expired and deletes it
// under a single write lock, preventing TOCTOU races with concurrent retrievals.
// Returns true if the drop was deleted, false if it was skipped (locked, not expired, or unreadable).
func (m *Manager) deleteIfExpired(id string, maxAge time.Duration, now time.Time) (bool, error) {
	// Skip drops that are currently locked (being retrieved)
	if !m.Locks.TryLock(id) {
		return false, nil
	}
	defer m.Locks.Unlock(id)

	// Load metadata to check timestamp (read directly, not via GetDropMetadata,
	// since we already hold the write lock)
	metaPath := filepath.Join(m.StorageDir, id, "meta")
	payload, err := loadEncryptedMetadata(metaPath, m.EncryptionKey, id)
	if err != nil {
		return false, nil
	}

	dropTime := time.Unix(payload.TimestampHour, 0)
	if now.Sub(dropTime) <= maxAge {
		return false, nil
	}

	// Drop is expired — delete it while still holding the write lock
	dropDir := filepath.Join(m.StorageDir, id)

	if m.Quota != nil {
		filePath := filepath.Join(dropDir, "data")
		if _, statErr := os.Stat(filePath); os.IsNotExist(statErr) {
			filePath = filepath.Join(dropDir, "file.enc")
		}
		if info, statErr := os.Stat(filePath); statErr == nil {
			m.Quota.Release(info.Size())
		}
	}

	if m.SecureDelete {
		return true, SecureDeleteDir(dropDir)
	}
	return true, os.RemoveAll(dropDir)
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

	// Release quota for the encrypted file size (try "data" first, fall back to legacy "file.enc")
	if m.Quota != nil {
		filePath := filepath.Join(dropDir, "data")
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			filePath = filepath.Join(dropDir, "file.enc")
		}
		if info, err := os.Stat(filePath); err == nil {
			m.Quota.Release(info.Size())
		}
	}

	if m.SecureDelete {
		return SecureDeleteDir(dropDir)
	}
	return os.RemoveAll(dropDir)
}
