# Threat Model

This document describes the threat model for Dead Drop, an anonymous file submission system designed for sensitive document exchange.

## System Overview

Dead Drop enables anonymous file submissions where:

- **Submitters** upload files via HTTP/Tor and receive an HMAC receipt
- **Retrievers** download files using the receipt as proof of authorization
- The **server** encrypts all files at rest and tracks no submitter identity
- Files are optionally destroyed after a single retrieval ("true dead drop" mode)

The system is designed to minimize metadata exposure and resist traffic analysis, brute-force enumeration, and insider threats.

## Trust Boundaries

```
                    ┌─────────────────────────────┐
                    │         Network              │
  Submitter ───────►│  (Tor / TLS / clearnet)     │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │       Dead Drop Server       │
                    │  ┌───────────────────────┐   │
                    │  │  Rate Limiter          │   │
                    │  │  Validator / Scrubber  │   │
                    │  │  Crypto Engine         │   │
                    │  │  Honeypot Manager      │   │
                    │  └───────────┬───────────┘   │
                    └──────────────┼───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │       Storage (disk)          │
                    │  Encrypted drops, key files,  │
                    │  metadata, .master.salt        │
                    └──────────────────────────────┘
```

**Boundary 1: Submitter / Retriever <-> Server**
- Network traffic is observable unless Tor is used
- The server never learns submitter identity (no authentication required)
- Receipt exchange happens out-of-band

**Boundary 2: Server <-> Storage**
- All drops are encrypted with AES-256-GCM before writing to disk
- Key files are optionally encrypted at rest with an Argon2id-derived master key
- Metadata is encrypted with per-drop HKDF-derived keys

**Boundary 3: Admin <-> Key Material**
- Master key passphrase is provided via environment variable, never stored on disk
- Key rotation requires both old and new passphrases

## Threat Actors

| Actor | Capability | Goal |
|-------|-----------|------|
| **Nation-state** | Full network surveillance, legal compulsion, endpoint compromise | Identify submitters, access drop contents |
| **Network observer** | Passive traffic analysis, timing correlation | Correlate submissions with retrievals |
| **Malicious insider** | Server access, disk access, log access | Read drop contents, identify submitters |
| **Opportunistic attacker** | Internet-facing attack surface, automated scanning | Enumerate drops, exfiltrate data |
| **Compromised server** | Full server process memory, disk access | Decrypt drops, tamper with data |

## Attack Scenarios and Mitigations

| Attack | Description | Mitigation | Residual Risk |
|--------|-------------|------------|---------------|
| **Traffic analysis** | Correlate upload/download timing via network observation | Tor hidden service; response jitter (50-200ms) | Tor guard node compromise; long-term statistical analysis |
| **Ciphertext swap** | Replace one drop's ciphertext with another's | AAD binds ciphertext to drop ID; AES-256-GCM authentication rejects tampered data | None (cryptographic guarantee) |
| **Timing correlation** | Use file timestamps to correlate submissions | Timestamps rounded to the hour; cleanup jitter +/-10 minutes | Filesystem-level timestamps (use `noatime` mount) |
| **Brute-force enumeration** | Guess drop IDs to discover files | 128-bit random ID space (2^128 possibilities); rate limiting (10 req/min/IP); HMAC receipt required for retrieval | Distributed brute-force (mitigated by ID space size) |
| **Path traversal** | Escape storage directory via crafted IDs | Strict regex validation: `^[a-f0-9]{32}$` | None (only 32-char hex accepted) |
| **Key compromise** | Attacker obtains encryption keys | Master key encryption at rest (Argon2id); memory zeroing after use; secure 3-pass file deletion | Cold boot attacks; memory forensics while server running |
| **Honeypot detection** | Distinguish honeypots from real drops | Honeypots use identical encryption, format, and storage; random 1-10KB content | Statistical analysis over many drops if attacker has disk access |
| **Metadata leakage** | EXIF/GPS data reveals submitter identity | Client-side EXIF stripping (JPEG APP markers, PNG text chunks); server-side scrubbing available | Unrecognized metadata formats |
| **Executable upload** | Malware distribution via the service | Magic number detection (ELF, PE, Mach-O); extension blocking; MIME type blocking; shebang detection | Polyglot files; novel executable formats |
| **CSRF upload** | Browser-based cross-site upload | `X-Dead-Drop-Upload: true` custom header required | None (browsers cannot set custom headers cross-origin) |
| **DoS / resource exhaustion** | Exhaust disk space or server resources | Configurable upload size limit (default 100MB); storage quota (`max_storage_gb`, `max_drops`); rate limiting | Application-layer floods above rate limit |

## Assumptions

1. **OS and hardware are trusted.** Dead Drop does not defend against kernel-level rootkits or hardware implants.
2. **`crypto/rand` is secure.** All random values (drop IDs, nonces, keys) rely on the Go `crypto/rand` package backed by the OS CSPRNG.
3. **AES-256-GCM and Argon2id are sound.** The system relies on the cryptographic strength of these algorithms.
4. **Tor is correctly configured.** When using Tor, the hidden service setup must follow Tor Project best practices.
5. **Receipt exchange is secure.** The out-of-band channel used to share receipts (e.g., Signal, PGP) is assumed to be confidential.

## Known Limitations

- **No forward secrecy for stored data.** If encryption keys are compromised, all encrypted drops (past and present) can be decrypted. The master key protects keys at rest but cannot provide forward secrecy.
- **SSD wear-leveling limits secure deletion.** The 3-pass overwrite is effective on HDDs but SSDs may retain data in spare blocks. Use full-disk encryption (LUKS/dm-crypt) as an additional layer.
- **No client authentication.** Anyone with network access (or the `.onion` address) can submit files. Rate limiting and quotas are the only upload-side controls.
- **Single-server architecture.** There is no replication or distributed storage. Server compromise means all drops are at risk.
- **Timestamp rounding is coarse.** Hour-rounded timestamps reduce precision but do not eliminate timing information entirely.

## Related Documents

- [Architecture](ARCHITECTURE.md) - System components and data flow
- [Key Management](KEY_MANAGEMENT.md) - Key hierarchy and rotation procedures
- [Deployment Guide](DEPLOYMENT_GUIDE.md) - Production hardening
- [Incident Response](INCIDENT_RESPONSE.md) - Breach response procedures
