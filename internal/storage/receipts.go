package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ReceiptManager generates and validates HMAC-based receipts.
type ReceiptManager struct {
	secret []byte
}

// NewReceiptManager loads or generates the receipt secret key.
// If masterKey is non-nil, the key file is encrypted at rest.
func NewReceiptManager(keyPath string, masterKey []byte) (*ReceiptManager, error) {
	secret, err := loadOrGenerateKey(keyPath, masterKey, []byte("receipt-key"))
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
