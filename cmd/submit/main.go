package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/scttfrdmn/dead-drop/internal/crypto"
	"github.com/scttfrdmn/dead-drop/internal/metadata"
	"golang.org/x/net/proxy"
)

type Config struct {
	ServerURL     string
	UseTor        bool
	TorProxy      string
	FilePath      string
	ScrubMetadata bool
	EncryptClient bool
	EncryptionKey string
}

type SubmitResponse struct {
	DropID   string `json:"drop_id"`
	Receipt  string `json:"receipt"`
	FileHash string `json:"file_hash"`
	Message  string `json:"message"`
}

func main() {
	config := Config{}
	genKey := flag.Bool("generate-key", false, "Generate a new encryption key and exit")
	flag.StringVar(&config.ServerURL, "server", "http://localhost:8080", "Dead drop server URL")
	flag.BoolVar(&config.UseTor, "tor", false, "Use Tor SOCKS5 proxy")
	flag.StringVar(&config.TorProxy, "tor-proxy", "127.0.0.1:9050", "Tor SOCKS5 proxy address")
	flag.StringVar(&config.FilePath, "file", "", "File to submit (required unless -generate-key)")
	flag.BoolVar(&config.ScrubMetadata, "scrub-metadata", true, "Strip EXIF/metadata before upload (recommended)")
	flag.BoolVar(&config.EncryptClient, "encrypt", false, "Encrypt file client-side before upload")
	keyFile := flag.String("key-file", "", "Read encryption key from file (recommended over -key)")
	flag.StringVar(&config.EncryptionKey, "key", "", "Encryption key (base64) - INSECURE: visible in process list, use -key-file instead")
	flag.Parse()

	// SECURITY: Read key from file instead of command-line args
	if *keyFile != "" {
		keyData, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
			os.Exit(1)
		}
		config.EncryptionKey = strings.TrimSpace(string(keyData))
	}

	// Handle key generation
	if *genKey {
		if err := GenerateAndPrintKey(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if config.FilePath == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if config.EncryptClient && config.EncryptionKey == "" {
		fmt.Fprintf(os.Stderr, "Error: -key is required when using -encrypt\n")
		flag.Usage()
		os.Exit(1)
	}

	if err := submitFile(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func submitFile(config Config) error {
	// Read file
	fileData, err := os.ReadFile(config.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	filename := filepath.Base(config.FilePath)

	// Client-side metadata scrubbing
	if config.ScrubMetadata {
		fmt.Println("Scrubbing metadata...")
		scrubber := metadata.NewScrubber()
		scrubbed := &bytes.Buffer{}
		if err := scrubber.ScrubFile(filename, bytes.NewReader(fileData), scrubbed); err != nil {
			fmt.Printf("Warning: metadata scrubbing failed: %v\n", err)
		} else {
			fileData = scrubbed.Bytes()
			fmt.Println("Metadata scrubbed")
		}
	}

	// Client-side encryption
	if config.EncryptClient {
		fmt.Println("Encrypting file...")
		keyBytes, err := base64.StdEncoding.DecodeString(config.EncryptionKey)
		if err != nil {
			return fmt.Errorf("invalid encryption key: %w", err)
		}

		encrypted := &bytes.Buffer{}
		if err := crypto.EncryptStream(keyBytes, bytes.NewReader(fileData), encrypted, nil); err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
		fileData = encrypted.Bytes()
		filename = filename + ".enc"
		fmt.Println("File encrypted")
	}

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := part.Write(fileData); err != nil {
		return fmt.Errorf("failed to write file data: %w", err)
	}

	writer.Close()

	// Create HTTP client
	client := &http.Client{}

	if config.UseTor {
		// Configure Tor SOCKS5 proxy
		proxyURL, err := url.Parse("socks5://" + config.TorProxy)
		if err != nil {
			return fmt.Errorf("failed to parse proxy URL: %w", err)
		}

		dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err != nil {
			return fmt.Errorf("failed to create proxy dialer: %w", err)
		}

		client.Transport = &http.Transport{
			Dial: dialer.Dial,
		}

		fmt.Println("Using Tor proxy:", config.TorProxy)
	}

	// Create request
	submitURL := config.ServerURL + "/submit"
	req, err := http.NewRequest("POST", submitURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	// CSRF protection header
	req.Header.Set("X-Dead-Drop-Upload", "true")

	fmt.Printf("Submitting file: %s\n", filepath.Base(config.FilePath))
	fmt.Printf("Server: %s\n", config.ServerURL)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var submitResp SubmitResponse
	if err := json.NewDecoder(resp.Body).Decode(&submitResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Println("\nFile submitted successfully")
	fmt.Println("\nDrop ID:")
	fmt.Printf("  %s\n", submitResp.DropID)
	fmt.Println("\nReceipt code:")
	fmt.Printf("  %s\n", submitResp.Receipt)
	fmt.Println("\nFile SHA-256:")
	fmt.Printf("  %s\n", submitResp.FileHash)
	fmt.Printf("\nRetrieve URL:\n  %s/retrieve?id=%s&receipt=%s\n",
		config.ServerURL, submitResp.DropID, submitResp.Receipt)
	fmt.Println("\nSave the drop ID and receipt - both are needed for retrieval.")

	return nil
}
