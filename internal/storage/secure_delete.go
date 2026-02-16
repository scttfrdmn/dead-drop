package storage

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// SecureDelete overwrites a file with multiple passes before removing it.
// Pass 1: zeros, Pass 2: ones (0xFF), Pass 3: random data, then os.Remove.
func SecureDelete(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	size := info.Size()
	if size == 0 {
		return os.Remove(path)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file for overwrite: %w", err)
	}

	buf := make([]byte, 4096)

	// Pass 1: zeros
	for i := range buf {
		buf[i] = 0x00
	}
	if err := overwriteFile(f, size, buf); err != nil {
		f.Close()
		return fmt.Errorf("zero pass failed: %w", err)
	}

	// Pass 2: ones
	for i := range buf {
		buf[i] = 0xFF
	}
	if err := overwriteFile(f, size, buf); err != nil {
		f.Close()
		return fmt.Errorf("ones pass failed: %w", err)
	}

	// Pass 3: random
	if err := overwriteFileRandom(f, size); err != nil {
		f.Close()
		return fmt.Errorf("random pass failed: %w", err)
	}

	f.Sync()
	f.Close()

	return os.Remove(path)
}

// SecureDeleteDir securely deletes all files in a directory, then removes the directory.
func SecureDeleteDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Directory doesn't exist, nothing to do
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if err := SecureDeleteDir(path); err != nil {
				return err
			}
		} else {
			if err := SecureDelete(path); err != nil {
				return err
			}
		}
	}

	return os.Remove(dir)
}

func overwriteFile(f *os.File, size int64, pattern []byte) error {
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	remaining := size
	for remaining > 0 {
		n := int64(len(pattern))
		if n > remaining {
			n = remaining
		}
		if _, err := f.Write(pattern[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	return f.Sync()
}

func overwriteFileRandom(f *os.File, size int64) error {
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	remaining := size
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			return err
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	return f.Sync()
}
