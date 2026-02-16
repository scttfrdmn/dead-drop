package monitoring

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// StatsFunc returns live storage statistics (totalBytes, dropCount).
type StatsFunc func() (int64, int)

// Metrics tracks operational counters for the dead-drop server.
type Metrics struct {
	uploadsTotal   atomic.Int64
	downloadsTotal atomic.Int64
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// RecordUpload increments the upload counter.
func (m *Metrics) RecordUpload() {
	m.uploadsTotal.Add(1)
}

// RecordDownload increments the download counter.
func (m *Metrics) RecordDownload() {
	m.downloadsTotal.Add(1)
}

// Handler returns an http.HandlerFunc that renders metrics in Prometheus
// text exposition format. The optional statsFunc provides live storage
// gauges; if nil, storage metrics are omitted.
func (m *Metrics) Handler(statsFunc StatsFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		fmt.Fprintf(w, "# HELP dead_drop_uploads_total Total number of successful uploads.\n")
		fmt.Fprintf(w, "# TYPE dead_drop_uploads_total counter\n")
		fmt.Fprintf(w, "dead_drop_uploads_total %d\n", m.uploadsTotal.Load())

		fmt.Fprintf(w, "# HELP dead_drop_downloads_total Total number of successful downloads.\n")
		fmt.Fprintf(w, "# TYPE dead_drop_downloads_total counter\n")
		fmt.Fprintf(w, "dead_drop_downloads_total %d\n", m.downloadsTotal.Load())

		if statsFunc != nil {
			totalBytes, dropCount := statsFunc()
			fmt.Fprintf(w, "# HELP dead_drop_storage_bytes Current storage usage in bytes.\n")
			fmt.Fprintf(w, "# TYPE dead_drop_storage_bytes gauge\n")
			fmt.Fprintf(w, "dead_drop_storage_bytes %d\n", totalBytes)
			fmt.Fprintf(w, "# HELP dead_drop_active_drops Current number of active drops.\n")
			fmt.Fprintf(w, "# TYPE dead_drop_active_drops gauge\n")
			fmt.Fprintf(w, "dead_drop_active_drops %d\n", dropCount)
		}
	}
}
