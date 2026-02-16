package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.Listen != "127.0.0.1:8080" {
		t.Errorf("Listen = %q, want %q", cfg.Server.Listen, "127.0.0.1:8080")
	}
	if cfg.Server.StorageDir != "./drops" {
		t.Errorf("StorageDir = %q, want %q", cfg.Server.StorageDir, "./drops")
	}
	if cfg.Server.MaxUploadMB != 100 {
		t.Errorf("MaxUploadMB = %d, want 100", cfg.Server.MaxUploadMB)
	}
	if cfg.Security.DeleteAfterRetrieve {
		t.Error("DeleteAfterRetrieve should default to false")
	}
	if cfg.Security.MaxAgeHours != 168 {
		t.Errorf("MaxAgeHours = %d, want 168", cfg.Security.MaxAgeHours)
	}
	if cfg.Security.RateLimitPerMin != 10 {
		t.Errorf("RateLimitPerMin = %d, want 10", cfg.Security.RateLimitPerMin)
	}
	if !cfg.Security.SecureDelete {
		t.Error("SecureDelete should default to true")
	}
	if cfg.Security.MaxStorageGB != 0 {
		t.Errorf("MaxStorageGB = %f, want 0", cfg.Security.MaxStorageGB)
	}
	if cfg.Security.MaxDrops != 0 {
		t.Errorf("MaxDrops = %d, want 0", cfg.Security.MaxDrops)
	}
	if !cfg.Logging.Startup {
		t.Error("Logging.Startup should default to true")
	}
	if !cfg.Logging.Errors {
		t.Error("Logging.Errors should default to true")
	}
	if cfg.Logging.Operations {
		t.Error("Logging.Operations should default to false")
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	yaml := `server:
  listen: "0.0.0.0:9090"
  storage_dir: "/tmp/drops"
  max_upload_mb: 50
security:
  delete_after_retrieve: true
  max_age_hours: 24
  rate_limit_per_min: 5
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}

	if cfg.Server.Listen != "0.0.0.0:9090" {
		t.Errorf("Listen = %q, want %q", cfg.Server.Listen, "0.0.0.0:9090")
	}
	if cfg.Server.StorageDir != "/tmp/drops" {
		t.Errorf("StorageDir = %q", cfg.Server.StorageDir)
	}
	if cfg.Server.MaxUploadMB != 50 {
		t.Errorf("MaxUploadMB = %d, want 50", cfg.Server.MaxUploadMB)
	}
	if !cfg.Security.DeleteAfterRetrieve {
		t.Error("DeleteAfterRetrieve should be true")
	}
	if cfg.Security.MaxAgeHours != 24 {
		t.Errorf("MaxAgeHours = %d, want 24", cfg.Security.MaxAgeHours)
	}
	if cfg.Security.RateLimitPerMin != 5 {
		t.Errorf("RateLimitPerMin = %d, want 5", cfg.Security.RateLimitPerMin)
	}
}

func TestLoadConfig_PartialOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// Only override listen, rest should remain defaults
	yaml := `server:
  listen: "0.0.0.0:3000"
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Server.Listen != "0.0.0.0:3000" {
		t.Errorf("Listen = %q, want %q", cfg.Server.Listen, "0.0.0.0:3000")
	}
	// Defaults should be preserved
	if cfg.Security.MaxAgeHours != 168 {
		t.Errorf("MaxAgeHours = %d, want 168 (default)", cfg.Security.MaxAgeHours)
	}
	if !cfg.Security.SecureDelete {
		t.Error("SecureDelete should be true (default)")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")

	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestSaveConfig_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	original := DefaultConfig()
	original.Server.Listen = "0.0.0.0:4444"
	original.Security.MaxAgeHours = 48

	if err := SaveConfig(path, original); err != nil {
		t.Fatalf("SaveConfig error: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}

	if loaded.Server.Listen != original.Server.Listen {
		t.Errorf("Listen = %q, want %q", loaded.Server.Listen, original.Server.Listen)
	}
	if loaded.Security.MaxAgeHours != original.Security.MaxAgeHours {
		t.Errorf("MaxAgeHours = %d, want %d", loaded.Security.MaxAgeHours, original.Security.MaxAgeHours)
	}
}

func TestSaveConfig_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if err := SaveConfig(path, DefaultConfig()); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestGetMaxFileAge(t *testing.T) {
	sec := &SecurityConfig{MaxAgeHours: 168}
	got := sec.GetMaxFileAge()
	want := 168 * time.Hour
	if got != want {
		t.Errorf("GetMaxFileAge() = %v, want %v", got, want)
	}
}

func TestSaveConfig_InvalidPath(t *testing.T) {
	err := SaveConfig("/nonexistent/dir/config.yaml", DefaultConfig())
	if err == nil {
		t.Fatal("expected error writing to invalid path")
	}
}

func TestGetMaxFileAge_Zero(t *testing.T) {
	sec := &SecurityConfig{MaxAgeHours: 0}
	got := sec.GetMaxFileAge()
	if got != 0 {
		t.Errorf("GetMaxFileAge() = %v, want 0", got)
	}
}
