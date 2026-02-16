package main

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"path/filepath"
	"time"

	"github.com/scttfrdmn/dead-drop/internal/config"
	"github.com/scttfrdmn/dead-drop/internal/metadata"
	"github.com/scttfrdmn/dead-drop/internal/ratelimit"
	"github.com/scttfrdmn/dead-drop/internal/storage"
	"github.com/scttfrdmn/dead-drop/internal/validation"
)

//go:embed static
var staticFiles embed.FS

type Server struct {
	storage   *storage.Manager
	config    *config.Config
	validator *validation.Validator
	scrubber  *metadata.Scrubber
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

	// Initialize storage
	storageManager, err := storage.NewManager(cfg.Server.StorageDir)
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

	server := &Server{
		storage:   storageManager,
		config:    cfg,
		validator: validation.NewValidator(cfg.Server.MaxUploadMB),
		scrubber:  metadata.NewScrubber(),
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
	http.DefaultServeMux = http.NewServeMux()

	// SECURITY: Rate limiting to prevent DoS and enumeration attacks
	rateLimit := cfg.Security.RateLimitPerMin
	if rateLimit <= 0 {
		rateLimit = 10 // Default to 10 if not configured
	}
	limiter := ratelimit.NewLimiter(rateLimit, 1*time.Minute)

	// Routes with rate limiting and security headers
	http.HandleFunc("/", securityHeaders(server.handleIndex))
	http.HandleFunc("/submit", securityHeaders(limiter.Middleware(server.handleSubmit)))
	http.HandleFunc("/retrieve", securityHeaders(limiter.Middleware(server.handleRetrieve)))

	if cfg.Logging.Startup {
		log.Printf("Dead drop server starting on %s", cfg.Server.Listen)
		log.Printf("Storage directory: %s", cfg.Server.StorageDir)
		log.Printf("Max upload size: %d MB", cfg.Server.MaxUploadMB)
		log.Printf("Delete after retrieve: %v", cfg.Security.DeleteAfterRetrieve)
		log.Printf("Secure delete: %v", cfg.Security.SecureDelete)
	}

	log.Fatal(http.ListenAndServe(cfg.Server.Listen, nil))
}

// securityHeaders wraps a handler with security response headers.
func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Cache-Control", "no-store")
		// Strip Server header (Go's default)
		w.Header().Del("Server")

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
	w.Write(data)
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
		log.Printf("Drop saved: %s", drop.ID)
	}

	// Return drop_id, receipt, and file hash
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
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

	io.Copy(w, reader)

	// Delete after retrieval if configured
	if s.config.Security.DeleteAfterRetrieve {
		if err := s.storage.DeleteDrop(dropID); err != nil {
			if s.config.Logging.Errors {
				log.Printf("Failed to delete drop %s after retrieval: %v", dropID, err)
			}
		} else if s.config.Logging.Operations {
			log.Printf("Drop %s deleted after retrieval", dropID)
		}
	}
}
