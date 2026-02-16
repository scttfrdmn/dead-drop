package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStorageKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestSaveLoadEncryptedMetadata_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta")
	key := testStorageKey(t)
	dropID := "abcdef0123456789abcdef0123456789"

	original := &MetadataPayload{
		Filename:      "test.txt",
		Receipt:       "abc123",
		TimestampHour: 1700000000,
		FileHash:      "deadbeef",
	}

	if err := saveEncryptedMetadata(path, key, dropID, original); err != nil {
		t.Fatalf("save error: %v", err)
	}

	loaded, err := loadEncryptedMetadata(path, key, dropID)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}

	if loaded.Filename != original.Filename {
		t.Errorf("Filename = %q, want %q", loaded.Filename, original.Filename)
	}
	if loaded.Receipt != original.Receipt {
		t.Errorf("Receipt = %q, want %q", loaded.Receipt, original.Receipt)
	}
	if loaded.TimestampHour != original.TimestampHour {
		t.Errorf("TimestampHour = %d, want %d", loaded.TimestampHour, original.TimestampHour)
	}
	if loaded.FileHash != original.FileHash {
		t.Errorf("FileHash = %q, want %q", loaded.FileHash, original.FileHash)
	}
}

func TestLoadEncryptedMetadata_LegacyFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta")
	key := testStorageKey(t)
	dropID := "abcdef0123456789abcdef0123456789"

	legacy := "filename=secret.pdf\nreceipt=r123\ntimestamp=1700000000\n"
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadEncryptedMetadata(path, key, dropID)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}

	if loaded.Filename != "secret.pdf" {
		t.Errorf("Filename = %q, want %q", loaded.Filename, "secret.pdf")
	}
	if loaded.Receipt != "r123" {
		t.Errorf("Receipt = %q, want %q", loaded.Receipt, "r123")
	}
	if loaded.TimestampHour != 1700000000 {
		t.Errorf("TimestampHour = %d, want 1700000000", loaded.TimestampHour)
	}
}

func TestDeriveMetadataKey_Deterministic(t *testing.T) {
	key := testStorageKey(t)

	k1, err := deriveMetadataKey(key, "drop1")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := deriveMetadataKey(key, "drop1")
	if err != nil {
		t.Fatal(err)
	}

	if string(k1) != string(k2) {
		t.Error("same inputs should derive same key")
	}
}

func TestDeriveMetadataKey_UniquePerDrop(t *testing.T) {
	key := testStorageKey(t)

	k1, _ := deriveMetadataKey(key, "drop1")
	k2, _ := deriveMetadataKey(key, "drop2")

	if string(k1) == string(k2) {
		t.Error("different drops should derive different keys")
	}
}

func TestDeriveMetadataKey_Length(t *testing.T) {
	key := testStorageKey(t)
	k, err := deriveMetadataKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 32 {
		t.Errorf("key length = %d, want 32", len(k))
	}
}

func TestRoundToHour(t *testing.T) {
	input := time.Date(2024, 1, 15, 14, 35, 22, 123456, time.UTC)
	got := roundToHour(input)
	want := time.Date(2024, 1, 15, 14, 0, 0, 0, time.UTC)

	if !got.Equal(want) {
		t.Errorf("roundToHour = %v, want %v", got, want)
	}
}

func TestRoundToHour_ExactHour(t *testing.T) {
	input := time.Date(2024, 1, 15, 14, 0, 0, 0, time.UTC)
	got := roundToHour(input)
	if !got.Equal(input) {
		t.Errorf("exact hour should be unchanged: %v != %v", got, input)
	}
}

func TestParseLegacyMetadata(t *testing.T) {
	data := "filename=report.pdf\nreceipt=abc123\ntimestamp=1700000000\n"
	payload, err := parseLegacyMetadata(data)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Filename != "report.pdf" {
		t.Errorf("Filename = %q", payload.Filename)
	}
	if payload.Receipt != "abc123" {
		t.Errorf("Receipt = %q", payload.Receipt)
	}
	if payload.TimestampHour != 1700000000 {
		t.Errorf("TimestampHour = %d", payload.TimestampHour)
	}
}

func TestParseLegacyMetadata_PartialData(t *testing.T) {
	data := "filename=test.txt\n"
	payload, err := parseLegacyMetadata(data)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Filename != "test.txt" {
		t.Errorf("Filename = %q", payload.Filename)
	}
	if payload.Receipt != "" {
		t.Errorf("Receipt should be empty, got %q", payload.Receipt)
	}
}

func TestLoadEncryptedMetadata_MissingFile(t *testing.T) {
	key := testStorageKey(t)
	_, err := loadEncryptedMetadata("/nonexistent/meta", key, "drop1")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestHexDecode(t *testing.T) {
	b, err := hexDecode("48656c6c6f")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "Hello" {
		t.Errorf("hexDecode = %q, want Hello", b)
	}
}

func TestHexDecode_Invalid(t *testing.T) {
	_, err := hexDecode("not-hex")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestSaveEncryptedMetadata_DifferentDropID(t *testing.T) {
	dir := t.TempDir()
	key := testStorageKey(t)
	dropID1 := "abcdef0123456789abcdef0123456789"
	dropID2 := "1234567890abcdef1234567890abcdef"

	path1 := filepath.Join(dir, "meta1")
	path2 := filepath.Join(dir, "meta2")

	payload := &MetadataPayload{Filename: "test.txt", Receipt: "r1", TimestampHour: 1700000000}

	saveEncryptedMetadata(path1, key, dropID1, payload)
	saveEncryptedMetadata(path2, key, dropID2, payload)

	// Should not be able to decrypt with wrong dropID
	_, err := loadEncryptedMetadata(path1, key, dropID2)
	if err == nil {
		t.Error("loading with wrong dropID should fail")
	}
}
