package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const metadataVersion = 1

// EncryptedMetadata is the on-disk JSON envelope for encrypted metadata.
type EncryptedMetadata struct {
	Version       int    `json:"version"`
	EncryptedData string `json:"encrypted_data"` // hex-encoded
	Nonce         string `json:"nonce"`           // hex-encoded
}

// MetadataPayload is the decrypted metadata content.
type MetadataPayload struct {
	Filename      string `json:"filename"`
	Receipt       string `json:"receipt"`
	TimestampHour int64  `json:"timestamp_hour"` // Unix timestamp rounded to hour
	FileHash      string `json:"file_hash,omitempty"`
}

// deriveMetadataKey derives a per-drop metadata key using HKDF from the storage key + drop ID.
func deriveMetadataKey(storageKey []byte, dropID string) ([]byte, error) {
	info := []byte("dead-drop-metadata-" + dropID)
	hkdfReader := hkdf.New(sha256.New, storageKey, nil, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("failed to derive metadata key: %w", err)
	}
	return key, nil
}

// roundToHour rounds a time to the nearest hour (truncate).
func roundToHour(t time.Time) time.Time {
	return t.Truncate(time.Hour)
}

// saveEncryptedMetadata encrypts and writes metadata to disk.
func saveEncryptedMetadata(path string, storageKey []byte, dropID string, payload *MetadataPayload) error {
	metaKey, err := deriveMetadataKey(storageKey, dropID)
	if err != nil {
		return err
	}
	defer ZeroBytes(metaKey)

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	defer ZeroBytes(plaintext)

	block, err := aes.NewCipher(metaKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	envelope := EncryptedMetadata{
		Version:       metadataVersion,
		EncryptedData: fmt.Sprintf("%x", ciphertext),
		Nonce:         fmt.Sprintf("%x", nonce),
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	return os.WriteFile(path, envelopeJSON, 0600)
}

// loadEncryptedMetadata reads and decrypts metadata from disk.
// It supports backward compatibility with old plaintext format.
func loadEncryptedMetadata(path string, storageKey []byte, dropID string) (*MetadataPayload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	// Try to parse as encrypted JSON envelope first
	var envelope EncryptedMetadata
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Version > 0 {
		return decryptMetadataEnvelope(&envelope, storageKey, dropID)
	}

	// Backward compatibility: parse old plaintext format
	return parseLegacyMetadata(string(data))
}

func decryptMetadataEnvelope(envelope *EncryptedMetadata, storageKey []byte, dropID string) (*MetadataPayload, error) {
	metaKey, err := deriveMetadataKey(storageKey, dropID)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(metaKey)

	ciphertext, err := hexDecode(envelope.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}
	defer ZeroBytes(ciphertext)

	nonce, err := hexDecode(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	block, err := aes.NewCipher(metaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
	}
	defer ZeroBytes(plaintext)

	var payload MetadataPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &payload, nil
}

// parseLegacyMetadata parses the old plaintext "key=value" format.
func parseLegacyMetadata(data string) (*MetadataPayload, error) {
	payload := &MetadataPayload{}
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "filename=") {
			payload.Filename = strings.TrimPrefix(line, "filename=")
		} else if strings.HasPrefix(line, "receipt=") {
			payload.Receipt = strings.TrimPrefix(line, "receipt=")
		} else if strings.HasPrefix(line, "timestamp=") {
			var ts int64
			fmt.Sscanf(line, "timestamp=%d", &ts)
			payload.TimestampHour = ts
		}
	}
	return payload, nil
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	_, err := fmt.Sscanf(s, "%x", &b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
