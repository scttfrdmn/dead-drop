package main

import (
	"encoding/base64"
	"fmt"

	"github.com/scttfrdmn/dead-drop/internal/crypto"
)

// GenerateAndPrintKey generates a new encryption key and prints it
func GenerateAndPrintKey() error {
	key, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(key)
	fmt.Println("Generated encryption key:")
	fmt.Println(encoded)
	fmt.Println("\nUse this key with: -encrypt -key=" + encoded)
	fmt.Println("Share this key securely with recipients who need to decrypt files.")

	return nil
}
