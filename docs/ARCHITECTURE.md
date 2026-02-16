# Architecture

This document describes the internal architecture, data flows, and design decisions of Dead Drop.

## Component Overview

```
                         ┌──────────────────────────────────┐
                         │          HTTP Server              │
                         │  (TLS 1.2+, timeouts, no logs)   │
                         └──────────────┬───────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              │                         │                         │
    ┌─────────▼─────────┐   ┌──────────▼──────────┐   ┌─────────▼─────────┐
    │   Rate Limiter     │   │  Security Headers   │   │   Timing Jitter   │
    │  (per-IP, 10/min)  │   │  (CSP, HSTS, etc.)  │   │   (50-200ms)      │
    └─────────┬─────────┘   └──────────┬──────────┘   └─────────┬─────────┘
              └─────────────────────────┼─────────────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              │                         │                         │
    ┌─────────▼─────────┐   ┌──────────▼──────────┐   ┌─────────▼─────────┐
    │   /submit          │   │   /retrieve          │   │   /metrics         │
    │   Upload handler   │   │   Download handler   │   │   Prometheus       │
    └─────────┬─────────┘   └──────────┬──────────┘   └───────────────────┘
              │                         │
              ▼                         ▼
    ┌───────────────────────────────────────────────────────────┐
    │                    Storage Manager                         │
    │  ┌─────────┐  ┌──────────┐  ┌───────┐  ┌──────────────┐  │
    │  │ Crypto   │  │ Receipts │  │ Locks │  │ Quota        │  │
    │  │ AES-GCM  │  │ HMAC-256 │  │ RWMux │  │ Size+Count   │  │
    │  ├─────────┤  └──────────┘  └───────┘  └──────────────┘  │
    │  │ HKDF     │                                             │
    │  │ Argon2id │  ┌──────────┐  ┌───────────────────────┐   │
    │  └─────────┘  │ Cleanup  │  │ Honeypot Manager      │   │
    │                │ (hourly) │  │ (canary drops)        │   │
    │                └──────────┘  └───────────────────────┘   │
    └───────────────────────────────────────────────────────────┘
              │                         │
    ┌─────────▼─────────┐   ┌──────────▼──────────┐
    │   Validator        │   │   Scrubber           │
    │  (type, size, ID)  │   │  (EXIF, PNG chunks)  │
    └───────────────────┘   └──────────────────────┘
```

## Data Flow: Upload

```
Client POST /submit
  │
  ├─ 1. Rate limit check (per-IP, 10 req/min sliding window)
  │     └─ 429 Too Many Requests if exceeded
  │
  ├─ 2. CSRF check: require X-Dead-Drop-Upload: true header
  │     └─ 403 Forbidden if missing
  │
  ├─ 3. Size check: http.MaxBytesReader (default 100MB)
  │     └─ 413 Request Entity Too Large if exceeded
  │
  ├─ 4. Validate file type
  │     ├─ Check magic numbers (block ELF, PE, Mach-O)
  │     ├─ Check shebang lines (block #!/bin/sh, etc.)
  │     ├─ Check file extension (block .exe, .dll, .sh, etc.)
  │     └─ Check MIME type (block executable types)
  │
  ├─ 5. Scrub metadata (if enabled)
  │     ├─ JPEG: strip APP0-APP15 markers (EXIF, GPS, etc.)
  │     └─ PNG: strip tEXt, zTXt, iTXt, tIME, pHYs, eXIf chunks
  │
  ├─ 6. Generate drop ID (16 random bytes → 32-char hex)
  │
  ├─ 7. Check quota (storage bytes + drop count)
  │     └─ 507 Insufficient Storage if exceeded
  │
  ├─ 8. Encrypt file: AES-256-GCM with AAD = drop ID
  │     └─ Write to <storage_dir>/<drop_id>/data
  │
  ├─ 9. Encrypt metadata: AES-256-GCM with HKDF-derived per-drop key
  │     ├─ Metadata includes: filename, content type, size, SHA-256 hash, timestamp (hour-rounded)
  │     └─ Write to <storage_dir>/<drop_id>/meta
  │
  ├─ 10. Generate receipt: HMAC-SHA256(receipt_key, drop_id) → 64-char hex
  │
  └─ 11. Return JSON response
        {
          "drop_id": "<32-char-hex>",
          "receipt": "<64-char-hex>",
          "sha256": "<file-hash>",
          "expires_at": "<timestamp>"
        }
```

## Data Flow: Download

```
Client GET /retrieve?id=<drop_id>&receipt=<receipt>
  │
  ├─ 1. Rate limit check
  │
  ├─ 2. Validate drop ID format: ^[a-f0-9]{32}$
  │     └─ 400 Bad Request if invalid
  │
  ├─ 3. Validate receipt: HMAC-SHA256 with constant-time comparison
  │     └─ 403 Forbidden if invalid
  │
  ├─ 4. Check honeypot list
  │     ├─ If honeypot: log alert, fire webhook (async), continue serving
  │     └─ Response is indistinguishable from real drop
  │
  ├─ 5. Acquire read lock for drop
  │
  ├─ 6. Decrypt metadata (HKDF-derived key)
  │     └─ Extract filename, content type
  │
  ├─ 7. Decrypt file (AES-256-GCM, verify AAD = drop ID)
  │     └─ Authentication failure = tampered data → 500 error
  │
  ├─ 8. Stream decrypted file to client
  │     └─ Set Content-Type, Content-Disposition headers
  │
  └─ 9. If delete_after_retrieve is enabled:
        ├─ Secure delete: 3-pass overwrite (zeros, ones, random)
        └─ Remove drop directory
```

## Encryption Layers

Dead Drop uses four layers of encryption:

```
Layer 1: Transport Encryption
  └─ TLS 1.2+ (clearnet) or Tor end-to-end encryption

Layer 2: File Encryption
  └─ AES-256-GCM
     ├─ Key: .encryption.key (32 bytes)
     ├─ Nonce: 12 bytes (random, prepended to ciphertext)
     ├─ AAD: drop ID (binds ciphertext to specific drop)
     └─ Tag: 16 bytes (appended to ciphertext)

Layer 3: Metadata Encryption
  └─ AES-256-GCM
     ├─ Key: HKDF-SHA256(encryption_key, "dead-drop-metadata-" + dropID)
     ├─ Nonce: 12 bytes (random)
     └─ Stored as JSON envelope: { version, nonce, encrypted_data }

Layer 4: Key Encryption at Rest
  └─ AES-256-GCM wrapping of .encryption.key and .receipt.key
     ├─ Wrapping key: Argon2id(passphrase, salt, time=3, mem=64MB, threads=4)
     ├─ Salt: 16 bytes in .master.salt
     └─ Encrypted key size: 60 bytes (12 nonce + 32 key + 16 tag)
```

## Storage Directory Layout

```
<storage_dir>/
├── .master.salt          # 16 bytes: Argon2id salt (if master key enabled)
├── .encryption.key       # 32 bytes (plaintext) or 60 bytes (encrypted)
├── .receipt.key          # 32 bytes (plaintext) or 60 bytes (encrypted)
├── .honeypots            # JSON array of honeypot drop IDs
│
├── <drop_id>/            # 32-char lowercase hex directory
│   ├── data              # Encrypted file (nonce ‖ ciphertext ‖ GCM tag)
│   └── meta              # Encrypted metadata JSON envelope
│
└── <drop_id>/            # Another drop...
    ├── data
    └── meta
```

- **Directory permissions:** `0700` (owner only)
- **File permissions:** `0600` (owner only)
- **Legacy support:** Older drops may use `file.enc` instead of `data`

## Concurrency Model

| Resource | Lock Type | Scope |
|----------|-----------|-------|
| Individual drop | `sync.RWMutex` | Per-drop directory |
| Cleanup cycle | `TryLock` | Non-blocking; skips locked drops |
| Quota counters | `sync.Mutex` | Global storage manager |
| Rate limiter | `sync.Mutex` | Per-IP visitor map |

- Downloads acquire a **read lock** on the drop, allowing concurrent reads
- Uploads acquire a **write lock** during save
- Cleanup uses `TryLock` to skip drops currently in use rather than blocking
- Stale rate limiter entries are cleaned every **5 minutes** (idle > 10 minutes)

## Request Lifecycle

Every HTTP request passes through middleware in this order:

1. **Rate limiting** - Per-IP sliding window (configurable, default 10/min)
2. **Security headers** - Applied to all responses:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'`
   - `Referrer-Policy: no-referrer`
   - `X-XSS-Protection: 1; mode=block`
   - `Cache-Control: no-store`
   - `Server` header removed
   - `Strict-Transport-Security: max-age=63072000; includeSubDomains` (TLS only)
3. **Timing jitter** - Random 50-200ms delay on every response
4. **Tor-only check** - If enabled, reject non-loopback connections (403)
5. **Handler** - Route-specific logic (`/submit`, `/retrieve`, `/metrics`)

## HTTP Server Hardening

| Setting | Value | Purpose |
|---------|-------|---------|
| `ReadTimeout` | 30 seconds | Limit slow-read attacks |
| `WriteTimeout` | 60 seconds | Limit slow-write attacks |
| `IdleTimeout` | 120 seconds | Reclaim idle connections |
| TLS minimum | TLS 1.2 | Reject weak protocol versions |
| Access logging | Disabled by default | Prevent IP/request logging for anonymity |
| `Server` header | Removed | Prevent server fingerprinting |

## Cleanup Process

- **Interval:** Approximately every hour, with +/-10 minute random jitter
- **Criteria:** Drops older than `max_age_hours` (default: 168 hours / 7 days)
- **Protected drops:** Honeypots are never cleaned up
- **Locking:** Uses `TryLock`; skips drops that are currently locked
- **Deletion:** Uses secure delete (3-pass overwrite) if `secure_delete: true`
- **Quota update:** Storage counters are decremented after each deletion

## Related Documents

- [Threat Model](THREAT_MODEL.md) - Attack scenarios and mitigations
- [Key Management](KEY_MANAGEMENT.md) - Key hierarchy and rotation
- [Deployment Guide](DEPLOYMENT_GUIDE.md) - Production configuration
- [Incident Response](INCIDENT_RESPONSE.md) - Breach response procedures
