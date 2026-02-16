# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Cleanup interval now includes random jitter (+/- 10 minutes) to prevent timing analysis (closes #4)

## [0.4.0] - 2026-02-15

### Added
- Honeypot/canary drop detection with configurable alert webhook (closes #3)
- `honeypots_enabled`, `honeypot_count`, `alert_webhook` config options
- Honeypot drops are auto-generated on startup, indistinguishable from real drops, and exempt from cleanup

### Changed
- Stored encrypted files renamed from `file.enc` to `data` to eliminate filename leakage (closes #2)
- Client-side encryption no longer appends `.enc` to filenames sent to server

### Security
- Encrypted file storage no longer reveals encryption status through filename extension

## [0.3.0] - 2026-02-15

### Added
- Master key encryption for key files at rest (`.encryption.key`, `.receipt.key`) using Argon2id key derivation and AES-256-GCM wrapping
- Automatic migration of plaintext key files to encrypted format when master key is configured
- TLS support with configurable certificate and key file paths
- HSTS header (`Strict-Transport-Security`) automatically added when TLS is enabled
- `master_key_env` config option to specify environment variable containing the master key passphrase
- `tls.cert_file` and `tls.key_file` config options for TLS certificate configuration
- Key rotation CLI tool (`cmd/rotate-keys`) for offline key rotation and re-wrapping
- Master key crypto primitives with salt management (`internal/crypto/masterkey.go`)

### Security
- Key files are no longer stored as plaintext when master key is configured (closes #1)
- TLS transport encryption prevents cleartext transmission in non-Tor deployments (closes #12)
- HSTS enforcement when TLS is active to prevent protocol downgrade attacks

## [0.2.0] - 2026-02-15

### Added
- Encrypted metadata with HKDF-derived per-drop keys and AES-GCM envelope format
- HMAC-SHA256 receipt authentication — retrieval now requires both drop ID and receipt
- Additional Authenticated Data (AAD) in GCM encryption binding ciphertext to drop ID
- Memory zeroing (`defer ZeroBytes()`) for sensitive buffers in crypto operations
- `Manager.Close()` method to zero encryption and receipt keys
- CSRF protection via `X-Dead-Drop-Upload: true` header on POST `/submit`
- Secure file deletion with 3-pass overwrite (zeros, ones, random) before removal
- HTTP security headers middleware: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Cache-Control`
- Random response delay jitter (50-200ms) for anti-fingerprinting
- Disk space quotas (`max_storage_gb`, `max_drops` config options)
- Per-drop read/write locking to prevent cleanup race conditions
- SHA-256 file integrity hash computed on upload and returned in response
- Web UI retrieval form with drop ID + receipt inputs
- `build-production` Makefile target with `-trimpath` and stripped symbols
- Backward compatibility for reading old plaintext metadata format

### Changed
- Submit response now returns `drop_id`, `receipt`, `file_hash`, and `message`
- Retrieve endpoint requires both `?id=<drop-id>&receipt=<receipt>` parameters
- Timestamps rounded to nearest hour to reduce correlation risk
- `EncryptStream`/`DecryptStream` now accept `aad []byte` parameter

### Security
- Metadata files no longer contain plaintext filenames, receipts, or precise timestamps
- Receipt codes are now HMAC-based (cryptographically bound to drop ID) instead of random
- Ciphertext is bound to its drop via AAD, preventing swap attacks
- CSRF protection prevents cross-origin upload attacks
- Files are securely overwritten before deletion (configurable via `secure_delete`)

## [0.1.0] - 2026-02-15

### Added
- Initial dead drop server with AES-256-GCM encryption at rest
- CLI submission tool with Tor SOCKS5 proxy support
- Client-side JPEG/PNG metadata scrubbing
- Client-side encryption option
- Web UI for file submission
- Automatic cleanup of expired drops
- Per-IP rate limiting
- Path traversal protection via drop ID validation
- Generic error messages to prevent information leakage
- Secure key input via `-key-file` flag
- Configuration via YAML file

[Unreleased]: https://github.com/scttfrdmn/dead-drop/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/scttfrdmn/dead-drop/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/scttfrdmn/dead-drop/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/scttfrdmn/dead-drop/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scttfrdmn/dead-drop/releases/tag/v0.1.0
