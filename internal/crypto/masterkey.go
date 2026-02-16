package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize         = 16
	masterSaltFile   = ".master.salt"
	plaintextKeySize = 32
	// EncryptedKeySize is nonce(12) + ciphertext(32) + GCM tag(16) = 60 bytes
	EncryptedKeySize = 60
)

// LoadOrGenerateSalt loads the master salt from disk, or generates and saves a new one.
func LoadOrGenerateSalt(storageDir string) ([]byte, error) {
	saltPath := filepath.Join(storageDir, masterSaltFile)

	// Try to load existing salt
	if data, err := os.ReadFile(saltPath); err == nil { // #nosec G304 -- path built from config
		if len(data) == saltSize {
			return data, nil
		}
	}

	// Generate new salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	if err := os.WriteFile(saltPath, salt, 0600); err != nil {
		return nil, fmt.Errorf("failed to save salt: %w", err)
	}

	return salt, nil
}

// DeriveMasterKey derives a 32-byte master key from a passphrase and salt using Argon2id.
func DeriveMasterKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
}

// EncryptKeyFile encrypts a plaintext key using AES-256-GCM with the master key.
// The purpose parameter is used as Additional Authenticated Data (AAD) to bind
// the ciphertext to its intended use (e.g., "encryption-key" or "receipt-key").
// Output format: nonce(12) || ciphertext+tag(32+16) = 60 bytes.
func EncryptKeyFile(masterKey, plaintextKey, purpose []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintextKey, purpose)
	return ciphertext, nil
}

// DecryptKeyFile decrypts an encrypted key file using AES-256-GCM with the master key.
// The purpose parameter must match the AAD used during encryption.
func DecryptKeyFile(masterKey, encryptedData, purpose []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return plaintext, nil
}
