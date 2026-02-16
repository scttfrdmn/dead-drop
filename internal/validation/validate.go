package validation

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Validator handles file validation
type Validator struct {
	AllowedTypes []string
	MaxSizeBytes int64
	BlockedTypes []string
}

// NewValidator creates a new file validator
func NewValidator(maxSizeMB int64) *Validator {
	return &Validator{
		MaxSizeBytes: maxSizeMB * 1024 * 1024,
		// Allow common document and image types
		AllowedTypes: []string{
			"image/jpeg",
			"image/png",
			"image/gif",
			"image/webp",
			"application/pdf",
			"text/plain",
			"application/zip",
			"application/x-zip-compressed",
			"application/msword",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		},
		// Block potentially dangerous types
		BlockedTypes: []string{
			"application/x-executable",
			"application/x-sh",
			"application/x-shellscript",
			"text/x-sh",
			"application/x-msdos-program",
		},
	}
}

// ValidateFile checks if file meets security requirements
func (v *Validator) ValidateFile(filename string, reader io.Reader) ([]byte, error) {
	// Read file data
	data, err := io.ReadAll(io.LimitReader(reader, v.MaxSizeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Check size
	if int64(len(data)) > v.MaxSizeBytes {
		return nil, fmt.Errorf("file exceeds maximum size of %d MB", v.MaxSizeBytes/(1024*1024))
	}

	// Detect content type
	contentType := http.DetectContentType(data)

	// Check if blocked
	for _, blocked := range v.BlockedTypes {
		if strings.Contains(contentType, blocked) {
			return nil, fmt.Errorf("file type not allowed: %s", contentType)
		}
	}

	// Additional checks for specific file types
	if err := v.validateSpecificType(filename, data); err != nil {
		return nil, err
	}

	return data, nil
}

// validateSpecificType performs type-specific validation
func (v *Validator) validateSpecificType(filename string, data []byte) error {
	// Check for executable flags
	if len(data) > 4 {
		// ELF magic number
		if bytes.Equal(data[0:4], []byte{0x7F, 0x45, 0x4C, 0x46}) {
			return fmt.Errorf("executable files not allowed")
		}
		// MZ header (Windows PE)
		if data[0] == 0x4D && data[1] == 0x5A {
			return fmt.Errorf("executable files not allowed")
		}
		// Mach-O magic numbers
		if bytes.Equal(data[0:4], []byte{0xFE, 0xED, 0xFA, 0xCE}) ||
			bytes.Equal(data[0:4], []byte{0xFE, 0xED, 0xFA, 0xCF}) ||
			bytes.Equal(data[0:4], []byte{0xCE, 0xFA, 0xED, 0xFE}) ||
			bytes.Equal(data[0:4], []byte{0xCF, 0xFA, 0xED, 0xFE}) {
			return fmt.Errorf("executable files not allowed")
		}
	}

	// Check for shell script shebangs
	if bytes.HasPrefix(data, []byte("#!/bin/sh")) ||
		bytes.HasPrefix(data, []byte("#!/bin/bash")) ||
		bytes.HasPrefix(data, []byte("#!/usr/bin/env")) {
		return fmt.Errorf("shell scripts not allowed")
	}

	// Check filename extension for additional safety
	lower := strings.ToLower(filename)
	dangerousExts := []string{".exe", ".dll", ".so", ".dylib", ".sh", ".bat", ".cmd", ".com", ".scr"}
	for _, ext := range dangerousExts {
		if strings.HasSuffix(lower, ext) {
			return fmt.Errorf("file extension not allowed: %s", ext)
		}
	}

	return nil
}

// GetContentType returns the detected content type
func (v *Validator) GetContentType(data []byte) string {
	return http.DetectContentType(data)
}
