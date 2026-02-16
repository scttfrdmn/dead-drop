package monitoring

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecordUploadIncrementsCounter(t *testing.T) {
	m := NewMetrics()
	m.RecordUpload()
	m.RecordUpload()
	m.RecordUpload()

	if got := m.uploadsTotal.Load(); got != 3 {
		t.Errorf("expected uploads_total = 3, got %d", got)
	}
}

func TestRecordDownloadIncrementsCounter(t *testing.T) {
	m := NewMetrics()
	m.RecordDownload()

	if got := m.downloadsTotal.Load(); got != 1 {
		t.Errorf("expected downloads_total = 1, got %d", got)
	}
}

func TestHandlerOutputFormat(t *testing.T) {
	m := NewMetrics()
	m.RecordUpload()
	m.RecordUpload()
	m.RecordDownload()

	statsFunc := func() (int64, int) {
		return 4096, 2
	}

	handler := m.Handler(statsFunc)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %s", ct)
	}

	body := rec.Body.String()

	// Verify Prometheus format with TYPE and HELP lines
	expectedLines := []string{
		"# HELP dead_drop_uploads_total",
		"# TYPE dead_drop_uploads_total counter",
		"dead_drop_uploads_total 2",
		"# HELP dead_drop_downloads_total",
		"# TYPE dead_drop_downloads_total counter",
		"dead_drop_downloads_total 1",
		"# HELP dead_drop_storage_bytes",
		"# TYPE dead_drop_storage_bytes gauge",
		"dead_drop_storage_bytes 4096",
		"# HELP dead_drop_active_drops",
		"# TYPE dead_drop_active_drops gauge",
		"dead_drop_active_drops 2",
	}

	for _, line := range expectedLines {
		if !strings.Contains(body, line) {
			t.Errorf("expected output to contain %q, got:\n%s", line, body)
		}
	}
}

func TestHandlerWithoutStatsFunc(t *testing.T) {
	m := NewMetrics()
	handler := m.Handler(nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	body := rec.Body.String()

	if strings.Contains(body, "storage_bytes") {
		t.Error("expected no storage_bytes when statsFunc is nil")
	}
	if strings.Contains(body, "active_drops") {
		t.Error("expected no active_drops when statsFunc is nil")
	}
}

func TestHandlerRejectsNonGet(t *testing.T) {
	m := NewMetrics()
	handler := m.Handler(nil)

	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405 for POST, got %d", rec.Code)
	}
}

func TestNoSensitiveDataInOutput(t *testing.T) {
	m := NewMetrics()
	m.RecordUpload()
	m.RecordDownload()

	statsFunc := func() (int64, int) {
		return 1024, 1
	}

	handler := m.Handler(statsFunc)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	body := strings.ToLower(rec.Body.String())

	sensitivePatterns := []string{
		"drop_id",
		"filename",
		"ip",
		"address",
		"receipt",
		"remote",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(body, pattern) {
			t.Errorf("metrics output should not contain sensitive pattern %q, got:\n%s", pattern, body)
		}
	}
}
