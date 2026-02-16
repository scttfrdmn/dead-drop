package storage

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"regexp"
)

// validDropID checks if a drop ID is valid hex string (prevents path traversal)
var validDropIDRegex = regexp.MustCompile(`^[a-f0-9]{32}$`)

// ValidateDropID checks if a drop ID is safe to use in file operations
func ValidateDropID(id string) error {
	if !validDropIDRegex.MatchString(id) {
		return fmt.Errorf("invalid drop ID format")
	}
	return nil
}

// ConstantTimeCompare compares two strings in constant time to prevent timing attacks
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SecureRandom generates cryptographically secure random bytes
func SecureRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	return b, nil
}

// SecureRandomHex generates a cryptographically secure random hex string
func SecureRandomHex(bytes int) (string, error) {
	b, err := SecureRandom(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ZeroBytes overwrites a byte slice with zeros (for sensitive data)
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
