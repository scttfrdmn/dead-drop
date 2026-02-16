# Dead Drop

[![CI](https://github.com/scttfrdmn/dead-drop/actions/workflows/ci.yml/badge.svg)](https://github.com/scttfrdmn/dead-drop/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/scttfrdmn/dead-drop)](https://goreportcard.com/report/github.com/scttfrdmn/dead-drop)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Secure and anonymous file submission system with no tracking of submitters.

## Features

- **Anonymous Submissions**: No IP logging, no user tracking
- **Tor Support**: Built-in SOCKS5 proxy support for CLI tool
- **Ephemeral Identifiers**: Random one-time IDs for each submission
- **Receipt Codes**: Submitters receive proof-of-submission codes
- **Dead Drop Model**: Files stored securely, retrievable by recipients
- **Metadata Scrubbing**: Foundation for removing file metadata (extensible)
- **Encryption Ready**: Built-in crypto utilities for at-rest encryption

## Architecture

```
dead-drop/
├── cmd/
│   ├── server/      # Web server for submissions and retrieval
│   └── submit/      # CLI tool for uploading files (with Tor support)
├── internal/
│   ├── crypto/      # Encryption/decryption utilities
│   ├── storage/     # File storage management
│   └── metadata/    # Metadata scrubbing (extensible)
└── web/             # Static web interface
```

## Quick Start

### 1. Build the binaries

```bash
# Build server
go build -o dead-drop-server ./cmd/server

# Build CLI submit tool
go build -o dead-drop-submit ./cmd/submit
```

### 2. Configure and run the server

**Option A: Using config file (recommended)**

```bash
# Copy example config
cp config.example.yaml config.yaml

# Edit config.yaml with your settings
# Then run:
./dead-drop-server -config config.yaml
```

**Option B: Using defaults**

```bash
# Run with defaults (no config file needed)
./dead-drop-server
```

See `config.example.yaml` for all configuration options including:
- Server listen address and storage directory
- Upload size limits
- Delete-after-retrieve behavior
- Automatic file expiration
- Logging controls

### 3. Submit files

**Via Web Browser:**
Navigate to `http://localhost:8080` and use the upload form.

**Via CLI (recommended for anonymity):**

```bash
# Generate encryption key (optional but recommended)
./dead-drop-submit -generate-key
# Outputs: Wq8zX... (example base64 key)

# Submit with client-side metadata scrubbing (default)
./dead-drop-submit -file photo.jpg -server http://localhost:8080

# Submit with client-side encryption + metadata scrubbing
./dead-drop-submit -file document.pdf \
  -server http://localhost:8080 \
  -encrypt \
  -key Wq8zX...

# Submit via Tor with all protections
./dead-drop-submit -file sensitive.pdf \
  -server http://yoursite.onion \
  -tor \
  -encrypt \
  -key Wq8zX...

# Disable metadata scrubbing (not recommended)
./dead-drop-submit -file data.txt \
  -server http://localhost:8080 \
  -scrub-metadata=false
```

**CLI Options:**
- `-file`: File to submit (required)
- `-server`: Server URL (default: `http://localhost:8080`)
- `-tor`: Use Tor SOCKS5 proxy (default: `false`)
- `-tor-proxy`: Tor proxy address (default: `127.0.0.1:9050`)
- `-scrub-metadata`: Strip EXIF/metadata before upload (default: `true`)
- `-encrypt`: Encrypt file client-side before upload (default: `false`)
- `-key`: Base64 encryption key (required with `-encrypt`)
- `-generate-key`: Generate new encryption key and exit

## Tor Hidden Service Setup

### 1. Install Tor
```bash
# macOS
brew install tor

# Ubuntu/Debian
apt-get install tor

# Start Tor
tor
```

### 2. Configure Tor Hidden Service

Edit `/etc/tor/torrc` (or `/usr/local/etc/tor/torrc` on macOS):

```
HiddenServiceDir /var/lib/tor/dead-drop/
HiddenServicePort 80 127.0.0.1:8080
```

Restart Tor:
```bash
sudo systemctl restart tor
```

Find your .onion address:
```bash
cat /var/lib/tor/dead-drop/hostname
```

### 3. Access via Tor

Users can now access your service at `http://youraddress.onion` using Tor Browser.

## Best Practices for Anonymity

### Client-Side Processing (Recommended)

Always process files **before** upload to minimize exposure:

```bash
# 1. Generate encryption key (share securely with recipient)
./dead-drop-submit -generate-key > encryption.key
# SECURITY: Keep encryption.key secure!

# 2. Submit with all client-side protections (SECURE METHOD)
./dead-drop-submit \
  -file sensitive_photo.jpg \
  -server http://yoursite.onion \
  -tor \
  -scrub-metadata \
  -encrypt \
  -key-file encryption.key

# WARNING: Using -key flag exposes key in process list (insecure)
# Only use -key-file for production
```

This ensures:
- ✓ Metadata stripped **before** transmission
- ✓ File encrypted **before** server sees it
- ✓ Anonymous network routing via Tor
- ✓ Server never sees plaintext or metadata

### Using torsocks

Alternative to built-in `-tor` flag:

```bash
torsocks ./dead-drop-submit \
  -file document.pdf \
  -server http://abc123.onion \
  -scrub-metadata \
  -encrypt \
  -key YOUR_KEY
```

## Retrieval

Files are retrieved by drop ID:
```
GET /retrieve?id=<drop-id>
```

The receipt code is NOT the drop ID - it's proof of submission. Drop IDs are stored server-side.

## Security Considerations

### Current Implementation
- No IP/user-agent logging on submit endpoint
- Random ephemeral submission IDs
- Receipt codes for proof of submission
- Configurable upload size limits

### Implemented Security Features
- ✓ **Client-side metadata scrubbing** (JPEG EXIF, PNG metadata) - strips before upload
- ✓ **Client-side encryption** (AES-256-GCM) - encrypts before server sees it
- ✓ **Server-side at-rest encryption** (AES-256-GCM) - double-layer protection
- ✓ Automatic file expiration/cleanup (configurable)
- ✓ Delete-after-retrieval option
- ✓ Content-type validation
- ✓ Executable file blocking
- ✓ Configurable upload size limits
- ✓ YAML configuration file support
- ✓ Optional logging controls (disable for production)

### Additional Hardening (TODO)
- [ ] Rate limiting per IP/connection
- [ ] Honeypot fields for web uploads
- [ ] PDF metadata stripping
- [ ] Office document metadata stripping
- [ ] Video/audio metadata stripping

### Production Deployment Checklist
- [ ] Disable all web server access logs
- [ ] Run server behind Tor hidden service
- [ ] Use encrypted filesystem for storage directory
- [ ] Set strict file permissions (0700 for dirs, 0600 for files)
- [ ] Enable automatic file cleanup/expiration
- [ ] Run server as non-root user
- [ ] Consider running in isolated container/VM
- [ ] Add monitoring without logging sensitive data

## AWS S3 Hosting (Static Site Only)

The web interface could be hosted on S3, but the **submission endpoint must remain server-side**:

```
┌─────────┐         ┌──────────┐         ┌────────────┐
│ S3/CDN  │────────>│  User's  │────────>│ Dead Drop  │
│ (HTML)  │         │  Browser │         │   Server   │
└─────────┘         └──────────┘         └────────────┘
   Static           Client-side             API Server
                    JavaScript              (Go binary)
```

This hybrid approach:
- ✓ Static HTML/JS served from S3/CloudFront
- ✓ Uploads POST directly to your server (regular or .onion)
- ✗ Loses anonymity if using regular domain (S3 logs CloudFront requests)
- ✓ Works if backend is .onion and users access via Tor

**Not recommended** unless you need CDN distribution - hosting static files via the Go server is simpler and more secure.

## Development

```bash
# Run tests
go test ./...

# Format code
go fmt ./...

# Run with verbose logging
./dead-drop-server -listen :8080
```

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Warning

This is a proof-of-concept implementation. Production use requires additional hardening, security audits, and operational security practices. Always consult security professionals for anonymous systems handling sensitive data.
