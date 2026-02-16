package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all server configuration
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Security SecurityConfig `yaml:"security"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig holds server settings
type ServerConfig struct {
	Listen      string        `yaml:"listen"`
	StorageDir  string        `yaml:"storage_dir"`
	MaxUploadMB int64         `yaml:"max_upload_mb"`
	TLS         TLSConfig     `yaml:"tls"`
	Metrics     MetricsConfig `yaml:"metrics"`
}

// MetricsConfig holds metrics endpoint settings
type MetricsConfig struct {
	Enabled       bool `yaml:"enabled"`
	LocalhostOnly bool `yaml:"localhost_only"`
}

// TLSConfig holds TLS certificate settings
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// SecurityConfig holds security settings
type SecurityConfig struct {
	DeleteAfterRetrieve bool    `yaml:"delete_after_retrieve"`
	MaxAgeHours         int     `yaml:"max_age_hours"`
	ScrubMetadata       bool    `yaml:"scrub_metadata"`
	RateLimitPerMin     int     `yaml:"rate_limit_per_min"`
	SecureDelete        bool    `yaml:"secure_delete"`
	MaxStorageGB        float64 `yaml:"max_storage_gb"`
	MaxDrops            int     `yaml:"max_drops"`
	MasterKeyEnv        string  `yaml:"master_key_env"`
	HoneypotsEnabled    bool    `yaml:"honeypots_enabled"`
	HoneypotCount       int     `yaml:"honeypot_count"`
	AlertWebhook        string  `yaml:"alert_webhook"`
	TorOnly             bool    `yaml:"tor_only"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Startup    bool   `yaml:"startup"`
	Errors     bool   `yaml:"errors"`
	Operations bool   `yaml:"operations"`
	LogDir     string `yaml:"log_dir"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:      "127.0.0.1:8080",
			StorageDir:  "./drops",
			MaxUploadMB: 100,
		},
		Security: SecurityConfig{
			DeleteAfterRetrieve: false,
			MaxAgeHours:         168, // 7 days
			ScrubMetadata:       false,
			RateLimitPerMin:     10,
			SecureDelete:        true,
			MaxStorageGB:        0, // 0 = unlimited
			MaxDrops:            0, // 0 = unlimited
		},
		Logging: LoggingConfig{
			Startup:    true,
			Errors:     true,
			Operations: false,
		},
	}
}

// LoadConfig loads configuration from file
func LoadConfig(path string) (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()

	// Read file
	data, err := os.ReadFile(path) // #nosec G304 -- config path from command-line flag
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// GetMaxFileAge returns the max file age as a duration
func (c *SecurityConfig) GetMaxFileAge() time.Duration {
	return time.Duration(c.MaxAgeHours) * time.Hour
}

// SaveConfig writes configuration to file
func SaveConfig(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
