package honeypot

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// Alerter sends webhook notifications for honeypot events.
type Alerter struct {
	webhookURL string
	client     *http.Client
}

// AlertPayload is the JSON body sent to the webhook endpoint.
type AlertPayload struct {
	Event      string `json:"event"`
	DropID     string `json:"drop_id"`
	Timestamp  string `json:"timestamp"`
	RemoteAddr string `json:"remote_addr"`
}

// NewAlerter creates an alerter that POSTs to the given webhook URL.
func NewAlerter(webhookURL string) *Alerter {
	return &Alerter{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Send fires the alert payload to the webhook asynchronously.
func (a *Alerter) Send(payload *AlertPayload) {
	payload.Timestamp = time.Now().UTC().Format(time.RFC3339)

	go func() {
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("Honeypot alerter: failed to marshal payload: %v", err)
			return
		}

		resp, err := a.client.Post(a.webhookURL, "application/json", bytes.NewReader(body)) // #nosec G107 -- webhook URL from config
		if err != nil {
			log.Printf("Honeypot alerter: webhook POST failed: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			log.Printf("Honeypot alerter: webhook returned status %d", resp.StatusCode)
		}
	}()
}
