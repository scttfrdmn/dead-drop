package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/scttfrdmn/dead-drop/internal/crypto"
	"github.com/scttfrdmn/dead-drop/internal/storage"
)

func main() {
	storageDir := flag.String("storage-dir", "./drops", "Path to storage directory")
	rewrapOnly := flag.Bool("rewrap-only", false, "Only re-wrap key files with new master key (no data re-encryption)")
	flag.Parse()

	oldPassphrase := os.Getenv("DEAD_DROP_OLD_MASTER_KEY")
	newPassphrase := os.Getenv("DEAD_DROP_MASTER_KEY")

	if newPassphrase == "" {
		log.Fatal("DEAD_DROP_MASTER_KEY environment variable must be set")
	}

	// Load salt (must already exist)
	salt, err := crypto.LoadOrGenerateSalt(*storageDir)
	if err != nil {
		log.Fatalf("Failed to load salt: %v", err)
	}

	// Derive keys
	var oldMasterKey []byte
	if oldPassphrase != "" {
		oldMasterKey = crypto.DeriveMasterKey(oldPassphrase, salt)
		defer crypto.ZeroBytes(oldMasterKey)
	}
	newMasterKey := crypto.DeriveMasterKey(newPassphrase, salt)
	defer crypto.ZeroBytes(newMasterKey)

	encKeyPath := filepath.Join(*storageDir, ".encryption.key")
	receiptKeyPath := filepath.Join(*storageDir, ".receipt.key")

	if *rewrapOnly {
		// Re-wrap key files with new master key
		if err := rewrapKeyFile(encKeyPath, oldMasterKey, newMasterKey); err != nil {
			log.Fatalf("Failed to rewrap encryption key: %v", err)
		}
		if err := rewrapKeyFile(receiptKeyPath, oldMasterKey, newMasterKey); err != nil {
			log.Fatalf("Failed to rewrap receipt key: %v", err)
		}
		fmt.Println("Key files re-wrapped successfully.")
		return
	}

	// Full rotation: generate new encryption key, re-encrypt all drops
	fmt.Println("Full key rotation: generating new encryption key and re-encrypting all drops...")

	// Load old encryption key
	oldEncKey, err := loadKey(encKeyPath, oldMasterKey)
	if err != nil {
		log.Fatalf("Failed to load old encryption key: %v", err)
	}
	defer crypto.ZeroBytes(oldEncKey)

	// Generate new encryption key
	newEncKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate new key: %v", err)
	}
	defer crypto.ZeroBytes(newEncKey)

	// Re-encrypt all drops
	entries, err := os.ReadDir(*storageDir)
	if err != nil {
		log.Fatalf("Failed to read storage directory: %v", err)
	}

	rotated := 0
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name()[0] == '.' {
			continue
		}

		dropID := entry.Name()
		if err := storage.ValidateDropID(dropID); err != nil {
			continue // skip non-drop directories
		}

		dropDir := filepath.Join(*storageDir, dropID)
		if err := reencryptDrop(dropDir, dropID, oldEncKey, newEncKey); err != nil {
			log.Fatalf("Failed to re-encrypt drop %s: %v", dropID, err)
		}
		rotated++
	}

	// Save new encryption key (encrypted with new master key)
	encrypted, err := crypto.EncryptKeyFile(newMasterKey, newEncKey)
	if err != nil {
		log.Fatalf("Failed to encrypt new key: %v", err)
	}
	if err := os.WriteFile(encKeyPath, encrypted, 0600); err != nil {
		log.Fatalf("Failed to write new encryption key: %v", err)
	}

	// Re-wrap receipt key with new master key
	if err := rewrapKeyFile(receiptKeyPath, oldMasterKey, newMasterKey); err != nil {
		log.Fatalf("Failed to rewrap receipt key: %v", err)
	}

	fmt.Printf("Key rotation complete: %d drops re-encrypted.\n", rotated)
}

// loadKey reads a key file, decrypting it if masterKey is provided.
func loadKey(path string, masterKey []byte) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from CLI flag
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	if masterKey == nil {
		if len(data) == 32 {
			return data, nil
		}
		return nil, fmt.Errorf("expected 32-byte plaintext key, got %d bytes", len(data))
	}

	if len(data) == crypto.EncryptedKeySize {
		return crypto.DecryptKeyFile(masterKey, data)
	}
	if len(data) == 32 {
		return data, nil // plaintext, not yet migrated
	}
	return nil, fmt.Errorf("unexpected key file size: %d bytes", len(data))
}

// rewrapKeyFile decrypts a key file with the old master key and re-encrypts with the new one.
func rewrapKeyFile(path string, oldMasterKey, newMasterKey []byte) error {
	plaintext, err := loadKey(path, oldMasterKey)
	if err != nil {
		return fmt.Errorf("failed to load key: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	encrypted, err := crypto.EncryptKeyFile(newMasterKey, plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}
	return nil
}

// reencryptDrop decrypts a drop's file and metadata with the old key and re-encrypts with the new key.
func reencryptDrop(dropDir, dropID string, oldKey, newKey []byte) error {
	// Re-encrypt data file (try "data" first, fall back to legacy "file.enc")
	filePath := filepath.Join(dropDir, "data")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		filePath = filepath.Join(dropDir, "file.enc")
	}
	if err := reencryptFile(filePath, dropID, oldKey, newKey); err != nil {
		return fmt.Errorf("failed to re-encrypt file: %w", err)
	}

	// Re-encrypt metadata
	metaPath := filepath.Join(dropDir, "meta")
	if err := reencryptFile(metaPath, dropID, oldKey, newKey); err != nil {
		return fmt.Errorf("failed to re-encrypt metadata: %w", err)
	}

	return nil
}

// reencryptFile decrypts and re-encrypts a single file using AES-GCM stream operations.
func reencryptFile(path, dropID string, oldKey, newKey []byte) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path built from validated drop ID
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Decrypt with old key
	decrypted := bytes.NewBuffer(nil)
	if err := crypto.DecryptStream(oldKey, bytes.NewReader(data), decrypted, []byte(dropID)); err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	// Re-encrypt with new key
	var encrypted bytes.Buffer
	if err := crypto.EncryptStream(newKey, decrypted, &encrypted, []byte(dropID)); err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// Write back
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0600) // #nosec G304
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, &encrypted); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
