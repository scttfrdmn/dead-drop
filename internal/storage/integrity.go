package storage

import (
	"crypto/sha256"
	"encoding/hex"
)

// computeSHA256 returns the hex-encoded SHA-256 hash of the data.
func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
