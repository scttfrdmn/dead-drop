package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// ReceiptManager generates and validates HMAC-based receipts.
type ReceiptManager struct {
	secret []byte
}

// NewReceiptManager loads or generates the receipt secret key.
func NewReceiptManager(keyPath string) (*ReceiptManager, error) {
	secret, err := loadOrGenerateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load receipt key: %w", err)
	}
	return &ReceiptManager{secret: secret}, nil
}

// Generate creates an HMAC-SHA256 receipt for the given drop ID.
func (rm *ReceiptManager) Generate(dropID string) string {
	mac := hmac.New(sha256.New, rm.secret)
	mac.Write([]byte(dropID))
	return hex.EncodeToString(mac.Sum(nil))
}

// Validate checks that a receipt matches the expected HMAC for the drop ID.
func (rm *ReceiptManager) Validate(dropID, receipt string) bool {
	expected := rm.Generate(dropID)
	return ConstantTimeCompare(expected, receipt)
}

// loadOrGenerateReceiptKey loads an existing key file or creates a new 32-byte key.
func loadOrGenerateReceiptKey(keyPath string) ([]byte, error) {
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 {
		return data, nil
	}

	key, err := SecureRandom(32)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to save receipt key: %w", err)
	}

	return key, nil
}
