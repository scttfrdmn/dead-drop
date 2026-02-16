package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scttfrdmn/dead-drop/internal/config"
	"github.com/scttfrdmn/dead-drop/internal/metadata"
	"github.com/scttfrdmn/dead-drop/internal/monitoring"
	"github.com/scttfrdmn/dead-drop/internal/storage"
	"github.com/scttfrdmn/dead-drop/internal/validation"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Server.StorageDir = dir

	sm, err := storage.NewManager(dir, nil)
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	sm.SecureDelete = false
	t.Cleanup(sm.Close)

	return &Server{
		storage:   sm,
		config:    cfg,
		validator: validation.NewValidator(cfg.Server.MaxUploadMB),
		scrubber:  metadata.NewScrubber(),
		metrics:   monitoring.NewMetrics(),
	}
}

func createMultipartFile(t *testing.T, fieldName, filename string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	return &buf, writer.FormDataContentType()
}

func TestHandleIndex_ServesHTML(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.handleIndex(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "Dead Drop") {
		t.Error("response should contain 'Dead Drop'")
	}
}

func TestHandleIndex_404ForNonRoot(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()

	s.handleIndex(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHandleSubmit_FullUpload(t *testing.T) {
	s := newTestServer(t)
	body, contentType := createMultipartFile(t, "file", "test.txt", []byte("hello world"))

	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()

	s.handleSubmit(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}

	if resp["drop_id"] == "" {
		t.Error("drop_id should not be empty")
	}
	if resp["receipt"] == "" {
		t.Error("receipt should not be empty")
	}
	if resp["file_hash"] == "" {
		t.Error("file_hash should not be empty")
	}
	if resp["message"] == "" {
		t.Error("message should not be empty")
	}
}

func TestHandleSubmit_CSRFRejection(t *testing.T) {
	s := newTestServer(t)
	body, contentType := createMultipartFile(t, "file", "test.txt", []byte("data"))

	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", contentType)
	// Missing X-Dead-Drop-Upload header
	rec := httptest.NewRecorder()

	s.handleSubmit(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing CSRF header", rec.Code)
	}
}

func TestHandleSubmit_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/submit", nil)
	rec := httptest.NewRecorder()

	s.handleSubmit(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestHandleRetrieve_ValidReceipt(t *testing.T) {
	s := newTestServer(t)

	// First, upload a file
	body, contentType := createMultipartFile(t, "file", "secret.txt", []byte("secret content"))
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()
	s.handleSubmit(rec, req)

	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)
	dropID := resp["drop_id"]
	receipt := resp["receipt"]

	// Retrieve the file
	req = httptest.NewRequest(http.MethodGet, "/retrieve?id="+dropID+"&receipt="+receipt, nil)
	rec = httptest.NewRecorder()
	s.handleRetrieve(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q", ct)
	}

	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "secret.txt") {
		t.Errorf("Content-Disposition = %q, should contain filename", cd)
	}

	if rec.Body.String() != "secret content" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "secret content")
	}
}

func TestHandleRetrieve_InvalidReceipt(t *testing.T) {
	s := newTestServer(t)

	// Upload a file first
	body, contentType := createMultipartFile(t, "file", "test.txt", []byte("data"))
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()
	s.handleSubmit(rec, req)

	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)
	dropID := resp["drop_id"]

	// Try to retrieve with wrong receipt
	req = httptest.NewRequest(http.MethodGet, "/retrieve?id="+dropID+"&receipt=wrongreceipt", nil)
	rec = httptest.NewRecorder()
	s.handleRetrieve(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestHandleRetrieve_MissingParams(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/retrieve", nil)
	rec := httptest.NewRecorder()
	s.handleRetrieve(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestHandleRetrieve_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/retrieve", nil)
	rec := httptest.NewRecorder()

	s.handleRetrieve(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestHandleRetrieve_InvalidIDLength(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/retrieve?id=short&receipt=abc", nil)
	rec := httptest.NewRecorder()

	s.handleRetrieve(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestHandleRetrieve_DeleteAfterRetrieve(t *testing.T) {
	s := newTestServer(t)
	s.config.Security.DeleteAfterRetrieve = true

	// Upload
	body, contentType := createMultipartFile(t, "file", "one-time.txt", []byte("one-time data"))
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()
	s.handleSubmit(rec, req)

	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)

	// First retrieve — should succeed
	req = httptest.NewRequest(http.MethodGet, "/retrieve?id="+resp["drop_id"]+"&receipt="+resp["receipt"], nil)
	rec = httptest.NewRecorder()
	s.handleRetrieve(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first retrieve: status = %d", rec.Code)
	}

	// Second retrieve — should fail (deleted)
	req = httptest.NewRequest(http.MethodGet, "/retrieve?id="+resp["drop_id"]+"&receipt="+resp["receipt"], nil)
	rec = httptest.NewRecorder()
	s.handleRetrieve(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("second retrieve: status = %d, want 404", rec.Code)
	}
}

func TestHandleSubmit_QuotaEnforcement(t *testing.T) {
	s := newTestServer(t)

	// Set up quota: max 1 drop
	qm, err := storage.NewQuotaManager(s.storage.StorageDir, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.storage.Quota = qm

	// First upload
	body, ct := createMultipartFile(t, "file", "first.txt", []byte("first"))
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()
	s.handleSubmit(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first upload: status = %d", rec.Code)
	}

	// Second upload should fail
	body, ct = createMultipartFile(t, "file", "second.txt", []byte("second"))
	req = httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec = httptest.NewRecorder()
	s.handleSubmit(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("second upload: status = %d, want 500", rec.Code)
	}
}

func TestTorOnlyMiddleware_AllowsLoopback(t *testing.T) {
	s := newTestServer(t)
	called := false

	handler := s.torOnlyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !called {
		t.Error("handler should be called for loopback")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestTorOnlyMiddleware_BlocksExternal(t *testing.T) {
	s := newTestServer(t)

	handler := s.torOnlyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for external IP")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestTorOnlyMiddleware_IPv6Loopback(t *testing.T) {
	s := newTestServer(t)
	called := false

	handler := s.torOnlyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:12345"
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !called {
		t.Error("IPv6 loopback should be allowed")
	}
}

func TestLocalhostOnly_AllowsLoopback(t *testing.T) {
	s := newTestServer(t)
	called := false

	handler := s.localhostOnly(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !called {
		t.Error("loopback should be allowed")
	}
}

func TestLocalhostOnly_BlocksExternal(t *testing.T) {
	s := newTestServer(t)

	handler := s.localhostOnly(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestSecurityHeaders_AllPresent(t *testing.T) {
	s := newTestServer(t)

	handler := s.securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	handler(rec, req)

	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"X-XSS-Protection":       "1; mode=block",
		"Cache-Control":          "no-store",
	}

	for name, want := range headers {
		got := rec.Header().Get(name)
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy should be set")
	}
}

func TestSecurityHeaders_HSTSOnlyWithTLS(t *testing.T) {
	s := newTestServer(t)
	s.tlsEnabled = false

	handler := s.securityHeaders(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if hsts := rec.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS should not be set without TLS: %q", hsts)
	}

	// Now with TLS
	s.tlsEnabled = true
	rec = httptest.NewRecorder()
	handler(rec, req)

	if hsts := rec.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Error("HSTS should be set with TLS")
	}
}

func TestMetrics_UploadCounter(t *testing.T) {
	s := newTestServer(t)

	body, ct := createMultipartFile(t, "file", "test.txt", []byte("data"))
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()
	s.handleSubmit(rec, req)

	// Check metrics
	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	s.metrics.Handler(nil)(metricsRec, metricsReq)

	metricsBody := metricsRec.Body.String()
	if !strings.Contains(metricsBody, "dead_drop_uploads_total 1") {
		t.Errorf("metrics should show 1 upload, got: %s", metricsBody)
	}
}

func TestMetrics_DownloadCounter(t *testing.T) {
	s := newTestServer(t)

	// Upload
	body, ct := createMultipartFile(t, "file", "test.txt", []byte("data"))
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()
	s.handleSubmit(rec, req)

	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)

	// Download
	req = httptest.NewRequest(http.MethodGet, "/retrieve?id="+resp["drop_id"]+"&receipt="+resp["receipt"], nil)
	rec = httptest.NewRecorder()
	s.handleRetrieve(rec, req)

	// Check metrics
	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	s.metrics.Handler(nil)(metricsRec, metricsReq)

	metricsBody := metricsRec.Body.String()
	if !strings.Contains(metricsBody, "dead_drop_downloads_total 1") {
		t.Errorf("metrics should show 1 download, got: %s", metricsBody)
	}
}

func TestHandleSubmit_ExecutableRejected(t *testing.T) {
	s := newTestServer(t)

	// ELF binary
	elf := make([]byte, 100)
	elf[0] = 0x7F
	elf[1] = 0x45
	elf[2] = 0x4C
	elf[3] = 0x46

	body, ct := createMultipartFile(t, "file", "malware", elf)
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()

	s.handleSubmit(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for executable upload", rec.Code)
	}
}

func TestHandleRetrieve_NonexistentDrop(t *testing.T) {
	s := newTestServer(t)

	// Generate a valid receipt for a non-existent drop
	fakeID := "abcdef0123456789abcdef0123456789"
	receipt := s.storage.Receipts.Generate(fakeID)

	req := httptest.NewRequest(http.MethodGet, "/retrieve?id="+fakeID+"&receipt="+receipt, nil)
	rec := httptest.NewRecorder()
	s.handleRetrieve(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestTorOnlyMiddleware_InvalidRemoteAddr(t *testing.T) {
	s := newTestServer(t)

	handler := s.torOnlyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "invalid-addr"
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestHandleSubmit_NoFile(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader("no file"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()

	s.handleSubmit(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing file", rec.Code)
	}
}

func TestHandleSubmit_WithMetadataScrubbing(t *testing.T) {
	s := newTestServer(t)
	s.config.Security.ScrubMetadata = true

	body, ct := createMultipartFile(t, "file", "photo.jpg", []byte("not really a jpeg"))
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()

	s.handleSubmit(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestHandleSubmit_WithLogging(t *testing.T) {
	s := newTestServer(t)
	s.config.Logging.Errors = true
	s.config.Logging.Operations = true

	body, ct := createMultipartFile(t, "file", "test.txt", []byte("logged upload"))
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()

	s.handleSubmit(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestHandleRetrieve_WithDeleteLogging(t *testing.T) {
	s := newTestServer(t)
	s.config.Security.DeleteAfterRetrieve = true
	s.config.Logging.Errors = true
	s.config.Logging.Operations = true

	body, ct := createMultipartFile(t, "file", "test.txt", []byte("data"))
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()
	s.handleSubmit(rec, req)

	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)

	req = httptest.NewRequest(http.MethodGet, "/retrieve?id="+resp["drop_id"]+"&receipt="+resp["receipt"], nil)
	rec = httptest.NewRecorder()
	s.handleRetrieve(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestLocalhostOnly_InvalidRemoteAddr(t *testing.T) {
	s := newTestServer(t)

	handler := s.localhostOnly(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "invalid"
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestHandleSubmit_ValidationFailedWithLogging(t *testing.T) {
	s := newTestServer(t)
	s.config.Logging.Errors = true

	// Upload a shell script
	body, ct := createMultipartFile(t, "file", "evil.sh", []byte("#!/bin/sh\nrm -rf /"))
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Dead-Drop-Upload", "true")
	rec := httptest.NewRecorder()

	s.handleSubmit(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// Silence the unused import warning for io
var _ = io.Discard
