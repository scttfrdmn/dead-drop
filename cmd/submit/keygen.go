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
	fmt.Println("\nSave to a file:  dead-drop-submit -generate-key | tail -1 > keyfile")
	fmt.Println("Use with:        dead-drop-submit -encrypt -key-file keyfile -file <path>")
	fmt.Println("Or via env var:  DEAD_DROP_KEY=" + encoded + " dead-drop-submit -encrypt -file <path>")
	fmt.Println("\nShare this key securely with recipients who need to decrypt files.")

	return nil
}
