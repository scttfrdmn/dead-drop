package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/scttfrdmn/dead-drop/internal/config"
	"github.com/scttfrdmn/dead-drop/internal/crypto"
	"github.com/scttfrdmn/dead-drop/internal/metadata"
	"github.com/scttfrdmn/dead-drop/internal/ratelimit"
	"github.com/scttfrdmn/dead-drop/internal/storage"
	"github.com/scttfrdmn/dead-drop/internal/validation"
)

//go:embed static
var staticFiles embed.FS

type Server struct {
	storage    *storage.Manager
	config     *config.Config
	validator  *validation.Validator
	scrubber   *metadata.Scrubber
	tlsEnabled bool
}

func main() {
	configPath := flag.String("config", "", "Path to config file (YAML)")
	flag.Parse()

	// Load configuration
	var cfg *config.Config
	var err error

	if *configPath != "" {
		cfg, err = config.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	} else {
		// Use defaults if no config file
		cfg = config.DefaultConfig()
	}

	// Derive master key from environment variable if configured
	var masterKey []byte
	if cfg.Security.MasterKeyEnv != "" {
		passphrase := os.Getenv(cfg.Security.MasterKeyEnv)
		if passphrase == "" {
			log.Fatalf("Master key environment variable %s is set in config but empty or unset", cfg.Security.MasterKeyEnv)
		}
		salt, saltErr := crypto.LoadOrGenerateSalt(cfg.Server.StorageDir)
		if saltErr != nil {
			log.Fatalf("Failed to load/generate master salt: %v", saltErr)
		}
		masterKey = crypto.DeriveMasterKey(passphrase, salt)
		defer crypto.ZeroBytes(masterKey)
	}

	// Initialize storage
	storageManager, err := storage.NewManager(cfg.Server.StorageDir, masterKey)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer storageManager.Close()

	// Configure secure delete from config
	storageManager.SecureDelete = cfg.Security.SecureDelete

	// Configure disk quotas if set
	if cfg.Security.MaxStorageGB > 0 || cfg.Security.MaxDrops > 0 {
		quota, err := storage.NewQuotaManager(cfg.Server.StorageDir, cfg.Security.MaxStorageGB, cfg.Security.MaxDrops)
		if err != nil {
			log.Fatalf("Failed to initialize quota manager: %v", err)
		}
		storageManager.Quota = quota
	}

	tlsEnabled := cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != ""

	server := &Server{
		storage:    storageManager,
		config:     cfg,
		validator:  validation.NewValidator(cfg.Server.MaxUploadMB),
		scrubber:   metadata.NewScrubber(),
		tlsEnabled: tlsEnabled,
	}

	// Start automatic cleanup
	maxAge := cfg.Security.GetMaxFileAge()
	if maxAge > 0 {
		cleanupConfig := storage.CleanupConfig{
			MaxAge:        maxAge,
			CheckInterval: 1 * time.Hour,
		}
		server.storage.StartCleanup(cleanupConfig)
		if cfg.Logging.Startup {
			log.Printf("Automatic cleanup enabled: files older than %v will be deleted", maxAge)
		}
	}

	// Disable default logging for anonymity
	mux := http.NewServeMux()

	// SECURITY: Rate limiting to prevent DoS and enumeration attacks
	rateLimit := cfg.Security.RateLimitPerMin
	if rateLimit <= 0 {
		rateLimit = 10 // Default to 10 if not configured
	}
	limiter := ratelimit.NewLimiter(rateLimit, 1*time.Minute)

	// Routes with rate limiting and security headers
	mux.HandleFunc("/", server.securityHeaders(server.handleIndex))
	mux.HandleFunc("/submit", server.securityHeaders(limiter.Middleware(server.handleSubmit)))
	mux.HandleFunc("/retrieve", server.securityHeaders(limiter.Middleware(server.handleRetrieve)))

	if cfg.Logging.Startup {
		log.Printf("Dead drop server starting on %s", cfg.Server.Listen)
		log.Printf("Storage directory: %s", cfg.Server.StorageDir)
		log.Printf("Max upload size: %d MB", cfg.Server.MaxUploadMB)
		log.Printf("Delete after retrieve: %v", cfg.Security.DeleteAfterRetrieve)
		log.Printf("Secure delete: %v", cfg.Security.SecureDelete)
	}

	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if tlsEnabled {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.Logging.Startup {
			log.Printf("TLS enabled with cert=%s key=%s", cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		}
		log.Fatal(srv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile))
	} else {
		log.Fatal(srv.ListenAndServe())
	}
}

// securityHeaders wraps a handler with security response headers.
func (s *Server) securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Cache-Control", "no-store")
		// Strip Server header (Go's default)
		w.Header().Del("Server")

		// HSTS when TLS is active
		if s.tlsEnabled {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		// Anti-fingerprint: random response delay (50-200ms jitter)
		jitter, _ := rand.Int(rand.Reader, big.NewInt(150))
		time.Sleep(time.Duration(50+jitter.Int64()) * time.Millisecond)

		next(w, r)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		// Fallback if embed fails
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Dead Drop</title></head>
<body>
<h1>Dead Drop - Anonymous File Submission</h1>
<form action="/submit" method="post" enctype="multipart/form-data">
<input type="file" name="file" required>
<button type="submit">Submit</button>
</form>
</body>
</html>`)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write(data)
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// CSRF protection: require custom header
	if r.Header.Get("X-Dead-Drop-Upload") != "true" {
		http.Error(w, "Missing required header", http.StatusBadRequest)
		return
	}

	// Limit upload size
	r.Body = http.MaxBytesReader(w, r.Body, s.config.Server.MaxUploadMB*1024*1024)

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file
	fileData, err := s.validator.ValidateFile(header.Filename, file)
	if err != nil {
		if s.config.Logging.Errors {
			log.Printf("Validation failed: %v", err)
		}
		// SECURITY: Generic error message to prevent information leakage
		http.Error(w, "Invalid file upload", http.StatusBadRequest)
		return
	}

	reader := bytes.NewReader(fileData)

	// Optionally scrub metadata (deprecated: prefer client-side)
	if s.config.Security.ScrubMetadata {
		scrubbed := &bytes.Buffer{}
		if err := s.scrubber.ScrubFile(header.Filename, reader, scrubbed); err != nil {
			if s.config.Logging.Errors {
				log.Printf("Metadata scrubbing failed: %v", err)
			}
			// Continue with original file if scrubbing fails
			reader = bytes.NewReader(fileData)
		} else {
			reader = bytes.NewReader(scrubbed.Bytes())
		}
	}

	// Save the drop
	drop, err := s.storage.SaveDrop(header.Filename, reader)
	if err != nil {
		if s.config.Logging.Errors {
			log.Printf("Error saving drop: %v", err)
		}
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	if s.config.Logging.Operations {
		// Drop ID is validated hex, safe to log
		log.Printf("Drop saved: %s", drop.ID) // #nosec G706 -- drop.ID is generated hex
	}

	// Return drop_id, receipt, and file hash
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"drop_id":   drop.ID,
		"receipt":   drop.Receipt,
		"file_hash": drop.FileHash,
		"message":   "File submitted successfully",
	})
}

func (s *Server) handleRetrieve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dropID := r.URL.Query().Get("id")
	receipt := r.URL.Query().Get("receipt")

	if dropID == "" || receipt == "" {
		http.Error(w, "Missing drop ID or receipt", http.StatusBadRequest)
		return
	}

	// Validate ID format
	if len(dropID) != 32 {
		http.Error(w, "Invalid drop ID", http.StatusBadRequest)
		return
	}

	// SECURITY: Validate HMAC receipt before returning file
	if !s.storage.Receipts.Validate(dropID, receipt) {
		http.Error(w, "Invalid receipt", http.StatusForbidden)
		return
	}

	filename, reader, err := s.storage.GetDrop(dropID)
	if err != nil {
		http.Error(w, "Drop not found", http.StatusNotFound)
		return
	}
	defer reader.Close()

	// Sanitize filename
	filename = filepath.Base(filename)

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Type", "application/octet-stream")

	_, _ = io.Copy(w, reader)

	// Delete after retrieval if configured
	if s.config.Security.DeleteAfterRetrieve {
		if err := s.storage.DeleteDrop(dropID); err != nil {
			if s.config.Logging.Errors {
				// dropID is validated 32-char hex at this point
				log.Printf("Failed to delete drop after retrieval: %v", err) // #nosec G706
			}
		} else if s.config.Logging.Operations {
			log.Printf("Drop deleted after retrieval") // #nosec G706
		}
	}
}
