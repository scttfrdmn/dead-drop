package validation

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewValidator(t *testing.T) {
	v := NewValidator(10)
	if v.MaxSizeBytes != 10*1024*1024 {
		t.Errorf("MaxSizeBytes = %d, want %d", v.MaxSizeBytes, 10*1024*1024)
	}
	if len(v.AllowedTypes) == 0 {
		t.Error("AllowedTypes should not be empty")
	}
	if len(v.BlockedTypes) == 0 {
		t.Error("BlockedTypes should not be empty")
	}
}

func TestValidateFile_PlainText(t *testing.T) {
	v := NewValidator(10)
	data, err := v.ValidateFile("readme.txt", bytes.NewReader([]byte("hello world")))
	if err != nil {
		t.Fatalf("ValidateFile error: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("data = %q, want %q", data, "hello world")
	}
}

func TestValidateFile_OversizedFile(t *testing.T) {
	v := NewValidator(1) // 1MB max
	bigData := make([]byte, 2*1024*1024)
	_, err := v.ValidateFile("big.txt", bytes.NewReader(bigData))
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !strings.Contains(err.Error(), "maximum size") {
		t.Errorf("error = %q, want it to mention maximum size", err.Error())
	}
}

func TestValidateFile_ExactlyAtLimit(t *testing.T) {
	v := NewValidator(1) // 1MB max
	data := make([]byte, 1*1024*1024)
	_, err := v.ValidateFile("exact.bin", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("file at exact limit should pass: %v", err)
	}
}

func TestValidateFile_ELFExecutable(t *testing.T) {
	v := NewValidator(10)
	elf := []byte{0x7F, 0x45, 0x4C, 0x46, 0x00, 0x00, 0x00, 0x00}
	_, err := v.ValidateFile("binary", bytes.NewReader(elf))
	if err == nil {
		t.Fatal("expected error for ELF executable")
	}
	if !strings.Contains(err.Error(), "executable") {
		t.Errorf("error = %q, want mention of executable", err.Error())
	}
}

func TestValidateFile_PEExecutable(t *testing.T) {
	v := NewValidator(10)
	pe := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}
	_, err := v.ValidateFile("test.bin", bytes.NewReader(pe))
	if err == nil {
		t.Fatal("expected error for PE executable")
	}
	if !strings.Contains(err.Error(), "executable") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestValidateFile_MachO(t *testing.T) {
	v := NewValidator(10)

	magics := [][]byte{
		{0xFE, 0xED, 0xFA, 0xCE, 0x00}, // 32-bit
		{0xFE, 0xED, 0xFA, 0xCF, 0x00}, // 64-bit
		{0xCE, 0xFA, 0xED, 0xFE, 0x00}, // 32-bit reversed
		{0xCF, 0xFA, 0xED, 0xFE, 0x00}, // 64-bit reversed
	}

	for _, magic := range magics {
		_, err := v.ValidateFile("macho", bytes.NewReader(magic))
		if err == nil {
			t.Errorf("expected error for Mach-O magic %x", magic[:4])
		}
	}
}

func TestValidateFile_ShellScripts(t *testing.T) {
	v := NewValidator(10)
	scripts := []string{
		"#!/bin/sh\necho hello",
		"#!/bin/bash\necho hello",
		"#!/usr/bin/env python3\nprint('hi')",
	}

	for _, s := range scripts {
		_, err := v.ValidateFile("script", bytes.NewReader([]byte(s)))
		if err == nil {
			t.Errorf("expected error for shebang: %q", s[:20])
		}
	}
}

func TestValidateFile_DangerousExtensions(t *testing.T) {
	v := NewValidator(10)
	extensions := []string{".exe", ".dll", ".so", ".dylib", ".sh", ".bat", ".cmd", ".com", ".scr"}

	for _, ext := range extensions {
		_, err := v.ValidateFile("file"+ext, bytes.NewReader([]byte("safe content")))
		if err == nil {
			t.Errorf("expected error for extension %s", ext)
		}
	}
}

func TestValidateFile_DangerousExtensions_CaseInsensitive(t *testing.T) {
	v := NewValidator(10)
	_, err := v.ValidateFile("FILE.EXE", bytes.NewReader([]byte("safe content")))
	if err == nil {
		t.Fatal("expected error for uppercase .EXE extension")
	}
}

func TestValidateFile_SafeExtensions(t *testing.T) {
	v := NewValidator(10)
	safe := []string{"photo.jpg", "doc.pdf", "notes.txt", "archive.zip", "image.png"}

	for _, name := range safe {
		_, err := v.ValidateFile(name, bytes.NewReader([]byte("safe content")))
		if err != nil {
			t.Errorf("ValidateFile(%q) error: %v", name, err)
		}
	}
}

func TestValidateFile_SmallDataSkipsMagicCheck(t *testing.T) {
	v := NewValidator(10)
	// Data too short for magic number check (<=4 bytes)
	_, err := v.ValidateFile("tiny.bin", bytes.NewReader([]byte{0x7F, 0x45}))
	if err != nil {
		t.Fatalf("short data should pass magic check: %v", err)
	}
}

func TestGetContentType(t *testing.T) {
	v := NewValidator(10)

	ct := v.GetContentType([]byte("hello world"))
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("GetContentType for text = %q, want text/plain", ct)
	}
}

func FuzzValidateFile(f *testing.F) {
	f.Add([]byte("hello"), "test.txt")
	f.Add([]byte{0x7F, 0x45, 0x4C, 0x46}, "binary")
	f.Add([]byte("#!/bin/sh\n"), "script.sh")

	v := NewValidator(10)

	f.Fuzz(func(t *testing.T, data []byte, filename string) {
		// Should not panic
		_, _ = v.ValidateFile(filename, bytes.NewReader(data))
	})
}
