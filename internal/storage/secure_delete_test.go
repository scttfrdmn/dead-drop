package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSecureDelete_FileRemoved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")

	if err := os.WriteFile(path, []byte("sensitive data here!"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := SecureDelete(path); err != nil {
		t.Fatalf("SecureDelete error: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be removed after SecureDelete")
	}
}

func TestSecureDelete_LargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.bin")

	// Create a file larger than the 4096 buffer
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	if err := SecureDelete(path); err != nil {
		t.Fatalf("SecureDelete error: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be removed")
	}
}

func TestSecureDelete_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")

	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	if err := SecureDelete(path); err != nil {
		t.Fatalf("SecureDelete error: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("empty file should be removed")
	}
}

func TestSecureDelete_MissingFile(t *testing.T) {
	err := SecureDelete("/nonexistent/file.txt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSecureDeleteDir_Recursive(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(subdir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}

	// Create files
	os.WriteFile(filepath.Join(subdir, "file1.txt"), []byte("data1"), 0600)
	os.WriteFile(filepath.Join(subdir, "nested", "file2.txt"), []byte("data2"), 0600)

	if err := SecureDeleteDir(subdir); err != nil {
		t.Fatalf("SecureDeleteDir error: %v", err)
	}

	if _, err := os.Stat(subdir); !os.IsNotExist(err) {
		t.Error("directory should be removed")
	}
}

func TestSecureDeleteDir_NonexistentDir(t *testing.T) {
	err := SecureDeleteDir("/nonexistent/dir")
	if err != nil {
		t.Errorf("nonexistent directory should return nil: %v", err)
	}
}

func TestSecureDeleteDir_WithMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "multi")
	os.MkdirAll(target, 0700)

	for i := 0; i < 5; i++ {
		name := filepath.Join(target, fmt.Sprintf("file%d.txt", i))
		os.WriteFile(name, []byte("data"), 0600)
	}

	if err := SecureDeleteDir(target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("directory should be removed")
	}
}

func TestSecureDelete_ExactBufferSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.bin")

	// Create file exactly 4096 bytes (buffer size)
	data := make([]byte, 4096)
	for i := range data {
		data[i] = 0xAA
	}
	os.WriteFile(path, data, 0600)

	if err := SecureDelete(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be removed")
	}
}

func TestSecureDeleteDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "empty")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}

	if err := SecureDeleteDir(target); err != nil {
		t.Fatalf("empty dir delete error: %v", err)
	}

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("empty directory should be removed")
	}
}
