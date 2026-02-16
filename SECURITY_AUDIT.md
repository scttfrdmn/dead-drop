# Security Audit Report - Dead Drop

**Date:** 2025-10-05
**Auditor:** Security & Counter-Intelligence Review
**Threat Model:** Nation-state adversaries, forensic analysis, traffic analysis, server compromise

---

## Executive Summary

Dead Drop is a proof-of-concept anonymous file submission system. While the architecture shows good security practices, **multiple critical vulnerabilities** exist that would compromise anonymity in a real-world deployment against sophisticated adversaries.

**Risk Level:** HIGH - Multiple critical issues found
**Recommendation:** DO NOT deploy in production without addressing Critical and High severity issues.

---

## Critical Vulnerabilities

### 1. **Timing Attack on File Uploads** ⚠️ CRITICAL
**File:** `cmd/server/main.go:139-146`
**Issue:** Validation errors return different response times depending on file content type.

```go
fileData, err := s.validator.ValidateFile(header.Filename, file)
if err != nil {
    http.Error(w, fmt.Sprintf("Invalid file: %v", err), http.StatusBadRequest)
}
```

**Attack:** Adversary can fingerprint what file types are being submitted by measuring response time variations.

**Fix:** Use constant-time validation and generic error messages.

---

### 2. **Metadata Leakage in Filenames** ⚠️ CRITICAL
**File:** `internal/storage/storage.go:121, 148`
**Issue:** Original filenames stored in plaintext in metadata file.

```go
meta := fmt.Sprintf("filename=%s\nreceipt=%s\ntimestamp=%d\n", filename, receipt, time.Now().Unix())
```

**Attack:** If server compromised, original filenames leak identity/context.
Example: `whistleblower_document_acme_corp.pdf` reveals source.

**Fix:** Hash or encrypt filenames, or strip entirely.

---

### 3. **Receipt Code Provides No Authentication** ⚠️ HIGH
**File:** `internal/storage/storage.go:89-92`
**Issue:** Receipt codes are random but not cryptographically bound to the upload.

**Attack:**
- Drop ID enumeration still possible (32-char hex = 128 bits, but linear search)
- Receipt can't prove ownership or prevent impersonation
- No way to verify receipt wasn't forged

**Fix:** Use HMAC(key, dropID) for receipts, or implement challenge-response.

---

### 4. **Path Traversal Vulnerability** ⚠️ CRITICAL
**File:** `internal/storage/storage.go:137, 151, 170`
**Issue:** Drop ID used directly in filepath without validation.

```go
dropDir := filepath.Join(m.StorageDir, id)
```

**Attack:** Malicious `id` like `../../etc/passwd` could access arbitrary files.

**Fix:** Validate `id` is alphanumeric hex before use.

---

### 5. **No Rate Limiting** ⚠️ HIGH
**File:** `cmd/server/main.go` (entire server)
**Issue:** No protection against:
- DoS attacks (fill disk with uploads)
- Drop ID enumeration attacks
- Timing analysis via repeated requests

**Fix:** Implement per-IP rate limiting, CAPTCHA for web uploads, and request throttling.

---

### 6. **Memory Not Zeroed After Use** ⚠️ HIGH
**File:** `internal/crypto/crypto.go:34, 66, 71`
**Issue:** Plaintext and keys stay in memory after encryption/decryption.

```go
plaintext, err := io.ReadAll(reader)  // Memory not wiped
ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
```

**Attack:** Memory dumps or swap files may contain plaintext.

**Fix:** Use `memguard` or explicitly zero memory after use.

---

### 7. **Nonce Reuse Risk on Key Reuse** ⚠️ MEDIUM
**File:** `internal/crypto/crypto.go:23-26`
**Issue:** If server key is reused across many encryptions, random nonce generation is safe BUT key is stored in plaintext on disk.

**Attack:** If `.encryption.key` is copied to another server and both encrypt data, nonce collision becomes possible.

**Fix:**
- Add key rotation
- Use deterministic nonce derivation (HKDF) + counter
- Encrypt the encryption key with a master key

---

### 8. **HTTP Header Fingerprinting** ⚠️ MEDIUM
**File:** `cmd/server/main.go` (HTTP handlers)
**Issue:** Default Go HTTP server reveals:
- Server version in headers
- TLS fingerprint
- Timing patterns unique to Go

**Attack:** Traffic analysis can identify this as a Go application, narrowing suspects.

**Fix:**
- Strip `Server` headers
- Use reverse proxy (nginx) to normalize headers
- Implement random response delays

---

### 9. **Timestamp Precision Leaks Info** ⚠️ MEDIUM
**File:** `internal/storage/storage.go:121, 130`
**Issue:** Nanosecond-precision timestamps stored.

```go
Timestamp: time.Now(),
timestamp=%d\n", filename, receipt, time.Now().Unix())
```

**Attack:** Correlate upload times with other events (e.g., "only employee X was at work at 3:47:23 AM").

**Fix:** Round timestamps to nearest hour or day.

---

### 10. **Client-Side Encryption Key Transmission** ⚠️ HIGH
**File:** `cmd/submit/main.go:91`
**Issue:** Encryption key passed via command-line flag.

```bash
./dead-drop-submit -key SECRETKEY123
```

**Attack:**
- Command-line arguments visible in `ps aux` output
- Logged in shell history
- Visible to other users on shared systems

**Fix:**
- Read key from file or stdin
- Use environment variable (slightly better)
- Prompt interactively with hidden input

---

## High Severity Issues

### 11. **No CSRF Protection on Web Uploads**
**File:** `cmd/server/main.go:122-172` (handleSubmit)
**Attack:** Malicious site can trick user's browser into uploading files via CSRF.
**Fix:** Add CSRF tokens or require custom headers.

---

### 12. **Unencrypted Metadata File**
**File:** `internal/storage/storage.go:121-124`
**Issue:** `meta` file contains filename, receipt, timestamp in plaintext.
**Attack:** Reveals sensitive info on server compromise.
**Fix:** Encrypt metadata file with same key as file.

---

### 13. **Drop ID Enumeration**
**File:** `internal/storage/storage.go:74-80`
**Issue:** 128-bit random IDs provide ~2^128 space, but:
- No proof-of-work requirement
- No authentication on retrieval
- Adversary can enumerate existing drops

**Attack:** Brute-force retrieval of all drops.
**Fix:** Require receipt code for retrieval, or add proof-of-work.

---

### 14. **No Transport Security Enforcement**
**File:** `cmd/server/main.go` (no HTTPS enforcement)
**Attack:** If not using Tor, unencrypted HTTP leaks everything to network observers.
**Fix:**
- Require HTTPS
- Add HSTS headers
- Reject non-.onion clearnet requests

---

### 15. **Cleanup Race Condition**
**File:** `internal/storage/cleanup.go:36-71`
**Issue:** Cleanup can delete files mid-retrieval.
**Attack:** Recipient downloads partial file, original is lost.
**Fix:** Use file locking or mark-for-deletion pattern.

---

## Medium Severity Issues

### 16. **Filename Extension Preserved**
**File:** `cmd/submit/main.go:101`
```go
filename = filename + ".enc"
```
Leaks file type even when encrypted. **Fix:** Use random filenames.

---

### 17. **Error Messages Too Detailed**
**File:** `cmd/server/main.go:144`
```go
http.Error(w, fmt.Sprintf("Invalid file: %v", err), http.StatusBadRequest)
```
**Attack:** Detailed errors help adversary probe validation logic.
**Fix:** Return generic "Invalid request" message.

---

### 18. **No Disk Space Limits**
**File:** `internal/storage/storage.go` (no quota checks)
**Attack:** Fill disk until server crashes.
**Fix:** Implement storage quotas.

---

### 19. **GCM Tag Only Protects Ciphertext**
**File:** `internal/crypto/crypto.go:39`
```go
ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
```
No additional authenticated data (AAD). **Fix:** Add dropID as AAD for binding.

---

### 20. **Go Garbage Collector Exposes Secrets**
Go's GC can move secrets in memory, leaving copies. Standard `[]byte` slices are not secure.
**Fix:** Use `github.com/awnumar/memguard` for key material.

---

## Low Severity Issues

### 21. **No File Integrity Verification**
Recipient can't verify file wasn't tampered with during storage.
**Fix:** Return SHA-256 hash with receipt.

### 22. **Predictable Cleanup Intervals**
**File:** `internal/storage/cleanup.go:70`
Cleanup runs exactly every hour. **Fix:** Add jitter.

### 23. **No Honeypot/Canary Detection**
Can't detect if adversary is probing server.
**Fix:** Add honeypot drops and alert on access.

### 24. **Static HTML Leaks Framework**
**File:** `cmd/server/static/index.html`
Comments, structure, or JS can fingerprint the application.
**Fix:** Minify and remove identifying marks.

### 25. **No Protection Against Malformed JPEG/PNG**
**File:** `internal/metadata/scrub.go:30-32, 103-108`
Malicious files could crash scrubber or exploit parser bugs.
**Fix:** Add robust error handling, fuzz testing.

---

## Forensic Concerns

### 26. **Deleted Files Recoverable**
```go
os.RemoveAll(dropDir)
```
Standard deletion doesn't overwrite data on disk.
**Fix:** Use secure deletion (overwrite with random data 7x per DoD 5220.22-M).

### 27. **Go Binary Contains Build Paths**
Go binaries embed source file paths.
**Fix:** Build with `-trimpath` flag.

### 28. **No Anti-Forensics for Logs**
Even with logging disabled, OS-level logs (syslog, systemd journal) may persist.
**Fix:** Run in container with ephemeral logging, or log to tmpfs.

---

## Operational Security Issues

### 29. **No Secure Key Distribution**
README shows passing keys via command line. Insecure.
**Fix:** Document using age, PGP, or Signal for key exchange.

### 30. **No Multi-Party Key Custody**
Single `.encryption.key` file is single point of failure.
**Fix:** Implement Shamir's Secret Sharing (M-of-N key recovery).

### 31. **No Secure Boot Verification**
Server could be backdoored at boot.
**Fix:** Document TPM-based measured boot for server host.

### 32. **No Network Isolation**
Server should only accept Tor connections.
**Fix:** Bind only to 127.0.0.1 and use Tor hidden service exclusively.

---

## Recommendations Priority

### Immediate (Block Deployment)
1. Fix path traversal (sanitize drop IDs)
2. Implement constant-time operations
3. Remove/encrypt filename metadata
4. Read encryption keys from secure input (not CLI args)
5. Add rate limiting

### Before Production
6. Implement CSRF protection
7. Encrypt metadata files
8. Add request authentication (HMAC receipts)
9. Zero memory after use
10. Add secure file deletion

### Hardening
11. Implement honeypots
12. Add file integrity verification
13. Use TLS with HSTS
14. Add disk quotas
15. Implement key rotation

### Operational
16. Document threat model
17. Provide secure key exchange guide
18. Add incident response plan
19. Implement monitoring/alerting
20. Conduct penetration testing

---

## Positive Security Findings

✅ AES-256-GCM is cryptographically sound
✅ Client-side encryption/scrubbing reduces server trust
✅ Random drop IDs have sufficient entropy
✅ File permissions (0600/0700) are restrictive
✅ No SQL injection (no database)
✅ Automatic cleanup reduces exposure window
✅ Tor integration is well-designed
✅ Configuration separation (YAML) is good practice

---

## Conclusion

This system has **good architectural foundations** but requires **substantial security hardening** before production use against sophisticated adversaries. The most critical issues are:

1. **Path traversal** - immediate exploit risk
2. **Timing attacks** - deanonymizes upload patterns
3. **Metadata leakage** - defeats anonymity on compromise
4. **Key exposure** - command-line args leak secrets

**Estimated remediation effort:** 40-60 hours for critical fixes, 100+ hours for comprehensive hardening.

**Final Risk Assessment:**
- Current: **UNSAFE for adversarial environments**
- Post-fixes: **MODERATE** (suitable for moderate threat models)
- Post-hardening: **HIGH** (suitable for whistleblowers, activists)

---

## References

- NIST SP 800-38D (GCM Mode)
- OWASP Top 10
- Tor Project Best Practices
- DoD 5220.22-M (Secure Deletion)
- CWE-22 (Path Traversal)
- CWE-208 (Timing Attacks)
