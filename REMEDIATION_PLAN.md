# Security Remediation Plan - Dead Drop

**Version:** 1.0
**Date:** 2025-10-05
**Estimated Total Effort:** 60-80 hours
**Priority:** Production-blocking issues first

---

## Executive Summary

This document provides a methodical, phased approach to addressing the 32 identified security vulnerabilities. The plan prioritizes issues by:
1. **Severity** (Critical → Low)
2. **Dependencies** (foundational fixes first)
3. **Implementation complexity** (quick wins vs. major refactors)
4. **Testing requirements** (isolated vs. integration testing)

---

## Phase 0: Foundation & Architecture (8-10 hours)

**Goal:** Establish secure foundations that other fixes depend on

### 0.1 Implement Memory Security Framework (4 hours)
**Dependencies:** None
**Blocks:** All crypto operations

**Tasks:**
1. Add `github.com/awnumar/memguard` dependency
2. Create `internal/secure/memory.go` with secure buffer handling
3. Refactor crypto operations to use `memguard.LockedBuffer`
4. Add automatic buffer wiping with defer patterns

**Implementation:**
```go
// internal/secure/memory.go
type SecureBuffer struct {
    buffer *memguard.LockedBuffer
}

func (s *SecureBuffer) Destroy() {
    s.buffer.Destroy()
}
```

**Testing:**
- Unit tests: Verify buffers are zeroed after use
- Memory profiling: Confirm no plaintext in heap dumps

**Deliverables:**
- [ ] `internal/secure/memory.go`
- [ ] Updated `internal/crypto/crypto.go` using secure buffers
- [ ] Test suite for memory security

---

### 0.2 Establish Encrypted Metadata Schema (4 hours)
**Dependencies:** Memory security
**Blocks:** Filename protection, timestamp obfuscation

**Design Decisions:**
1. **What to encrypt:** Filename, receipt, timestamp
2. **Key derivation:** HKDF from storage key + drop ID
3. **Format:** JSON encrypted with AES-GCM

**Schema:**
```json
{
  "version": 1,
  "encrypted_data": "base64...",
  "nonce": "base64..."
}
```

**Decrypted payload:**
```json
{
  "filename_hash": "sha256...",
  "receipt": "hex...",
  "timestamp_rounded": 1696550400  // rounded to hour
}
```

**Implementation:**
- `internal/storage/metadata.go` - EncryptedMetadata type
- Backward compatibility: Detect old plaintext format, migrate on read

**Testing:**
- Unit tests: Encryption/decryption round-trip
- Migration test: Old format → new format

**Deliverables:**
- [ ] `internal/storage/metadata.go`
- [ ] Migration path for existing drops
- [ ] Test suite

---

## Phase 1: Critical Security Fixes (20-25 hours)

**Goal:** Eliminate all CRITICAL and HIGH severity vulnerabilities

### 1.1 Encrypted Metadata Implementation (6 hours)
**Dependencies:** Phase 0.2
**Fixes:** #2 (Metadata Leakage), #12 (Unencrypted Metadata), #9 (Timestamp Precision)

**Tasks:**
1. Implement `EncryptedMetadata.Save()` and `Load()` methods
2. Update `SaveDrop()` to use encrypted metadata
3. Update `GetDrop()` to decrypt metadata
4. Remove plaintext filename from responses (use hash)
5. Round timestamps to nearest hour

**Changes:**
```go
// internal/storage/storage.go
type EncryptedMetadata struct {
    FilenameHash    string
    ReceiptHMAC     string
    TimestampHour   int64  // Unix timestamp rounded to hour
}

func (m *Manager) SaveDrop(filename string, reader io.Reader) (*Drop, error) {
    // Hash filename instead of storing plaintext
    filenameHash := sha256.Sum256([]byte(filename))

    // Encrypt metadata
    meta := EncryptedMetadata{
        FilenameHash: hex.EncodeToString(filenameHash[:]),
        // ...
    }
}
```

**Testing:**
- Unit tests: Verify encryption/decryption
- Integration tests: Upload → retrieve with encrypted metadata
- Security test: Verify no plaintext filenames on disk

**Deliverables:**
- [ ] Updated storage.go with encrypted metadata
- [ ] Filename hashing implementation
- [ ] Timestamp rounding to hour
- [ ] Test suite

---

### 1.2 HMAC-Based Receipt Authentication (8 hours)
**Dependencies:** Phase 0.2
**Fixes:** #3 (Receipt Authentication), #13 (Drop ID Enumeration)

**Design:**
- Receipt = HMAC(server_secret, dropID || timestamp)
- Retrieval requires valid receipt + dropID
- Server secret stored in `.receipt.key` (separate from encryption key)

**New Retrieval Flow:**
1. Client provides: dropID + receipt
2. Server validates: `ConstantTimeCompare(receipt, HMAC(secret, dropID))`
3. Return file only if receipt is valid

**API Changes:**
```
OLD: GET /retrieve?id=<drop-id>
NEW: GET /retrieve?id=<drop-id>&receipt=<receipt-hmac>
```

**Implementation:**
```go
// internal/storage/receipts.go
type ReceiptManager struct {
    secret []byte
}

func (r *ReceiptManager) Generate(dropID string) string {
    mac := hmac.New(sha256.New, r.secret)
    mac.Write([]byte(dropID))
    return hex.EncodeToString(mac.Sum(nil))
}

func (r *ReceiptManager) Validate(dropID, receipt string) bool {
    expected := r.Generate(dropID)
    return storage.ConstantTimeCompare(receipt, expected)
}
```

**Breaking Change:** Requires CLI update

**Testing:**
- Unit tests: HMAC generation/validation
- Integration tests: Full upload/download with receipt validation
- Security tests:
  - Invalid receipt rejected
  - Drop enumeration without receipt fails
  - Timing attack resistance

**Deliverables:**
- [ ] `internal/storage/receipts.go`
- [ ] Updated server handlers requiring receipts
- [ ] Updated CLI to use receipts
- [ ] Test suite
- [ ] Migration guide for existing drops

---

### 1.3 Memory Zeroing for Crypto Operations (6 hours)
**Dependencies:** Phase 0.1
**Fixes:** #6 (Memory Not Zeroed)

**Tasks:**
1. Refactor `EncryptStream()` to use secure buffers
2. Refactor `DecryptStream()` to use secure buffers
3. Add defer cleanup for all sensitive data
4. Zero encryption keys on Manager.Close()

**Implementation Pattern:**
```go
func EncryptStream(key []byte, reader io.Reader, writer io.Writer) error {
    secureKey := memguard.NewBufferFromBytes(key)
    defer secureKey.Destroy()

    plaintext, err := io.ReadAll(reader)
    defer func() {
        storage.ZeroBytes(plaintext)
    }()

    // ... encryption
}
```

**Testing:**
- Unit tests: Verify cleanup called
- Memory dump tests: No plaintext in heap after operations
- Fuzzing: Ensure cleanup happens even on panics

**Deliverables:**
- [ ] Updated crypto.go with secure buffers
- [ ] Manager.Close() method for cleanup
- [ ] Test suite with memory inspection

---

### 1.4 CSRF Protection (5 hours)
**Dependencies:** None
**Fixes:** #11 (No CSRF Protection)

**Approach:** SameSite cookies + custom header requirement

**Implementation:**
1. For web uploads: Require `X-Dead-Drop-Upload: true` header
2. For API uploads: Require same custom header (CLI already does this)
3. Add CORS restrictions (no cross-origin uploads)

**Changes:**
```go
// cmd/server/main.go
func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
    // SECURITY: CSRF protection
    if r.Header.Get("X-Dead-Drop-Upload") != "true" {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // ... rest of handler
}
```

**Frontend:**
```javascript
// cmd/server/static/index.html
fetch('/submit', {
    method: 'POST',
    body: formData,
    headers: {
        'X-Dead-Drop-Upload': 'true'
    }
});
```

**Testing:**
- Unit tests: Reject requests without header
- Integration tests: Web upload flow works
- Security tests: CSRF attack scenarios blocked

**Deliverables:**
- [ ] Updated server handler with CSRF check
- [ ] Updated web frontend with header
- [ ] Updated CLI to include header
- [ ] Test suite

---

## Phase 2: High-Priority Hardening (15-20 hours)

**Goal:** Address remaining HIGH severity issues

### 2.1 Nonce Management & Key Protection (6 hours)
**Dependencies:** Phase 0.1
**Fixes:** #7 (Nonce Reuse Risk)

**Approach:** Encrypt storage encryption key with master key

**Architecture:**
```
Master Key (in memory, from env var)
    └─> encrypts Storage Encryption Key (on disk)
            └─> encrypts file data
```

**Implementation:**
1. Generate master key from secure passphrase (PBKDF2)
2. Store encrypted storage key on disk
3. Decrypt storage key to memory on startup
4. Add key rotation mechanism (generate new, re-encrypt all files)

**Configuration:**
```yaml
security:
  master_key_env: "DEAD_DROP_MASTER_KEY"  # Environment variable name
  key_rotation_days: 90  # Auto-rotate storage keys
```

**Testing:**
- Unit tests: Key derivation, encryption, decryption
- Integration tests: Full lifecycle with encrypted keys
- Security tests: Verify storage key never plaintext on disk

**Deliverables:**
- [ ] `internal/crypto/keymanagement.go`
- [ ] Updated Manager initialization
- [ ] Key rotation CLI tool
- [ ] Test suite
- [ ] Documentation

---

### 2.2 Secure File Deletion (4 hours)
**Dependencies:** None
**Fixes:** #26 (Deleted Files Recoverable)

**Approach:** DoD 5220.22-M 7-pass overwrite

**Implementation:**
```go
// internal/storage/secure_delete.go
func SecureDelete(path string) error {
    file, err := os.OpenFile(path, os.O_RDWR, 0)
    if err != nil {
        return err
    }
    defer file.Close()

    stat, _ := file.Stat()
    size := stat.Size()

    // DoD 5220.22-M: 7 passes
    patterns := []byte{0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00}
    for _, pattern := range patterns {
        file.Seek(0, 0)
        io.CopyN(file, &patternReader{pattern}, size)
        file.Sync()  // Force to disk
    }

    // Final pass: random data
    file.Seek(0, 0)
    io.CopyN(file, rand.Reader, size)
    file.Sync()

    return os.Remove(path)
}
```

**Configuration:**
```yaml
security:
  secure_delete: true  # Enable secure deletion
  overwrite_passes: 7  # Number of overwrite passes
```

**Testing:**
- Unit tests: Verify overwrites happen
- Forensic tests: Use data recovery tools to verify
- Performance tests: Measure impact on deletion time

**Deliverables:**
- [ ] `internal/storage/secure_delete.go`
- [ ] Updated DeleteDrop() to use secure deletion
- [ ] Configuration option
- [ ] Test suite

---

### 2.3 HTTP Header Hardening (3 hours)
**Dependencies:** None
**Fixes:** #8 (HTTP Header Fingerprinting)

**Tasks:**
1. Strip Server header
2. Add security headers (HSTS, CSP, X-Frame-Options)
3. Implement random response delays (50-200ms jitter)
4. Add reverse proxy configuration guide (nginx)

**Implementation:**
```go
// internal/server/middleware.go
func SecurityHeaders(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Strip identifying headers
        w.Header().Set("Server", "")

        // Security headers
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Content-Security-Policy", "default-src 'none'")

        // Random delay (anti-fingerprinting)
        delay := time.Duration(50 + rand.Intn(150)) * time.Millisecond
        time.Sleep(delay)

        next(w, r)
    }
}
```

**Documentation:**
- Nginx reverse proxy config
- TLS configuration recommendations
- HSTS preload setup

**Testing:**
- Integration tests: Verify headers present
- Security tests: Fingerprinting attempts
- Performance tests: Measure delay impact

**Deliverables:**
- [ ] `internal/server/middleware.go`
- [ ] Applied to all routes
- [ ] Nginx config template
- [ ] Test suite

---

### 2.4 Disk Space Quotas (3 hours)
**Dependencies:** None
**Fixes:** #18 (No Disk Space Limits)

**Approach:** Track storage usage, enforce limits

**Implementation:**
```go
// internal/storage/quota.go
type QuotaManager struct {
    maxBytes      int64
    currentBytes  int64
    mu            sync.RWMutex
}

func (q *QuotaManager) Reserve(bytes int64) error {
    q.mu.Lock()
    defer q.mu.Unlock()

    if q.currentBytes + bytes > q.maxBytes {
        return ErrQuotaExceeded
    }

    q.currentBytes += bytes
    return nil
}

func (q *QuotaManager) Release(bytes int64) {
    q.mu.Lock()
    defer q.mu.Unlock()
    q.currentBytes -= bytes
}
```

**Configuration:**
```yaml
server:
  max_storage_gb: 100  # Total storage limit
  max_drops: 10000     # Maximum number of drops
```

**Testing:**
- Unit tests: Quota enforcement
- Integration tests: Upload rejection when full
- Stress tests: Concurrent quota management

**Deliverables:**
- [ ] `internal/storage/quota.go`
- [ ] Integrated into SaveDrop()
- [ ] Configuration options
- [ ] Test suite

---

### 2.5 Additional Authenticated Data in GCM (2 hours)
**Dependencies:** Phase 1.2 (HMAC receipts)
**Fixes:** #19 (GCM Tag Only Protects Ciphertext)

**Approach:** Include drop ID and timestamp as AAD

**Implementation:**
```go
func EncryptStream(key []byte, reader io.Reader, writer io.Writer, aad []byte) error {
    // ...
    ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
    // ...
}

// Usage
aad := []byte(fmt.Sprintf("%s:%d", dropID, timestamp))
crypto.EncryptStream(key, data, file, aad)
```

**Impact:** Prevents ciphertext from being moved between drops

**Testing:**
- Unit tests: Verify AAD binding
- Security tests: Attempt to swap ciphertexts between drops

**Deliverables:**
- [ ] Updated EncryptStream/DecryptStream signatures
- [ ] AAD generation in SaveDrop
- [ ] Test suite

---

## Phase 3: Medium Priority Improvements (12-15 hours)

**Goal:** Address MEDIUM severity issues and operational improvements

### 3.1 Filename Randomization (2 hours)
**Dependencies:** Phase 1.1
**Fixes:** #16 (Filename Extension Preserved)

**Implementation:**
```go
// Don't preserve extension, use random names
filename = fmt.Sprintf("%s.dat", generateID())  // Always .dat
```

**Testing:**
- Integration tests: Verify random names
- CLI tests: Receipt still works

**Deliverables:**
- [ ] Updated filename generation
- [ ] Test suite

---

### 3.2 Cleanup Race Condition Fix (3 hours)
**Dependencies:** None
**Fixes:** #15 (Cleanup Race Condition)

**Approach:** File locking during retrieval

**Implementation:**
```go
// internal/storage/locks.go
type DropLock struct {
    locks map[string]*sync.RWMutex
    mu    sync.Mutex
}

func (d *DropLock) Lock(id string) {
    d.mu.Lock()
    lock, exists := d.locks[id]
    if !exists {
        lock = &sync.RWMutex{}
        d.locks[id] = lock
    }
    d.mu.Unlock()

    lock.Lock()
}
```

**Testing:**
- Concurrency tests: Simultaneous retrieve + cleanup
- Integration tests: Verify no data loss

**Deliverables:**
- [ ] `internal/storage/locks.go`
- [ ] Integrated into GetDrop/DeleteDrop/Cleanup
- [ ] Test suite

---

### 3.3 File Integrity Verification (3 hours)
**Dependencies:** None
**Fixes:** #21 (No File Integrity Verification)

**Approach:** SHA-256 hash returned with receipt

**Implementation:**
```go
type Drop struct {
    // ...
    SHA256Hash string
}

// Return hash with receipt
json.NewEncoder(w).Encode(map[string]string{
    "receipt": drop.Receipt,
    "sha256":  drop.SHA256Hash,
})
```

**CLI Enhancement:**
```bash
./dead-drop-submit -file doc.pdf
# Output:
# Receipt: abc123...
# SHA-256: def456...
```

**Testing:**
- Unit tests: Hash generation
- Integration tests: Verify hash matches
- Security tests: Tamper detection

**Deliverables:**
- [ ] Hash generation in SaveDrop
- [ ] Hash verification option in retrieval
- [ ] CLI output enhancement
- [ ] Test suite

---

### 3.4 Honeypot Implementation (4 hours)
**Dependencies:** None
**Fixes:** #23 (No Honeypot Detection)

**Approach:** Canary drops that alert on access

**Implementation:**
```go
// internal/monitoring/honeypot.go
type Honeypot struct {
    canaryDrops map[string]bool
    alertFunc   func(dropID, ip string)
}

func (h *Honeypot) IsCanary(dropID string) bool {
    return h.canaryDrops[dropID]
}

func (h *Honeypot) TriggerAlert(dropID, ip string) {
    h.alertFunc(dropID, ip)
}
```

**Configuration:**
```yaml
security:
  honeypots_enabled: true
  honeypot_count: 5  # Number of canary drops to create
  alert_webhook: "https://..."  # Alert destination
```

**Testing:**
- Integration tests: Canary access triggers alert
- Security tests: Verify canaries indistinguishable from real drops

**Deliverables:**
- [ ] `internal/monitoring/honeypot.go`
- [ ] Auto-generation of canary drops
- [ ] Alert mechanism
- [ ] Test suite

---

## Phase 4: Operational & Low Priority (8-10 hours)

### 4.1 Build Hardening (1 hour)
**Dependencies:** None
**Fixes:** #27 (Go Binary Contains Build Paths)

**Implementation:**
```makefile
# Makefile
build-production:
	go build -trimpath \
	         -ldflags="-s -w -X main.version=$(VERSION)" \
	         -o dead-drop-server ./cmd/server
	go build -trimpath \
	         -ldflags="-s -w" \
	         -o dead-drop-submit ./cmd/submit
```

**Testing:**
- Binary analysis: Verify no source paths
- String analysis: Check for identifying info

**Deliverables:**
- [ ] Updated Makefile
- [ ] Build verification script

---

### 4.2 Anti-Forensics Logging (2 hours)
**Dependencies:** None
**Fixes:** #28 (No Anti-Forensics for Logs)

**Approach:** Log to tmpfs, automatic rotation

**Documentation:**
```bash
# Run with ephemeral logging
mkdir /tmp/dead-drop-logs
mount -t tmpfs -o size=100M tmpfs /tmp/dead-drop-logs
./dead-drop-server -log-dir /tmp/dead-drop-logs
```

**Docker Example:**
```dockerfile
VOLUME ["/tmp/logs"]
CMD ["dead-drop-server", "-log-dir", "/tmp/logs"]
```

**Testing:**
- Integration tests: Verify logs in tmpfs
- Reboot tests: Confirm logs don't persist

**Deliverables:**
- [ ] Documentation updates
- [ ] Docker compose example
- [ ] Systemd unit file example

---

### 4.3 Network Isolation (2 hours)
**Dependencies:** None
**Fixes:** #32 (No Network Isolation)

**Approach:** Bind to localhost only, document Tor setup

**Configuration:**
```yaml
server:
  listen: "127.0.0.1:8080"  # Localhost only
  tor_only: true  # Reject non-Tor requests
```

**Implementation:**
```go
// Detect Tor connections
func isTorConnection(r *http.Request) bool {
    // Check for Tor2Web header
    if r.Header.Get("X-Tor2Web") != "" {
        return true
    }
    // Check if coming from localhost (hidden service)
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    return host == "127.0.0.1" || host == "::1"
}
```

**Testing:**
- Integration tests: Reject non-Tor when enabled
- Tor tests: Accept Tor hidden service connections

**Deliverables:**
- [ ] Tor detection logic
- [ ] Configuration option
- [ ] Updated Tor setup documentation

---

### 4.4 Key Distribution Documentation (1 hour)
**Dependencies:** None
**Fixes:** #29 (No Secure Key Distribution)

**Create:** `docs/KEY_MANAGEMENT.md`

**Topics:**
- PGP key exchange workflow
- Signal Protocol for key sharing
- age encryption for key files
- QR code generation for keys
- Multi-party key custody

**Deliverables:**
- [ ] `docs/KEY_MANAGEMENT.md`
- [ ] Example scripts

---

### 4.5 Monitoring Without Logging (2 hours)
**Dependencies:** None
**Operational requirement**

**Approach:** Metrics without sensitive data

**Implementation:**
```go
// internal/monitoring/metrics.go
type Metrics struct {
    TotalUploads   int64
    TotalDownloads int64
    StorageUsed    int64
    ActiveDrops    int64
}

// Expose metrics endpoint (no sensitive data)
http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
    // Prometheus-style metrics without identifying info
    fmt.Fprintf(w, "dead_drop_uploads_total %d\n", metrics.TotalUploads)
    fmt.Fprintf(w, "dead_drop_storage_bytes %d\n", metrics.StorageUsed)
})
```

**Testing:**
- Integration tests: Verify no sensitive data exposed
- Security tests: Metrics don't leak drop IDs

**Deliverables:**
- [ ] `internal/monitoring/metrics.go`
- [ ] Prometheus integration guide
- [ ] Test suite

---

## Phase 5: Testing & Documentation (10-12 hours)

### 5.1 Comprehensive Test Suite (6 hours)

**Unit Tests:**
- All new modules (100% coverage target)
- Crypto operations
- Storage operations
- Authentication logic

**Integration Tests:**
- Full upload/download flows
- CSRF protection
- Rate limiting
- Receipt validation

**Security Tests:**
- Path traversal attempts
- Timing attack resistance
- Memory leak verification
- Forensic recovery attempts

**Fuzzing:**
- Crypto inputs
- Receipt validation
- File uploads
- Drop ID validation

**Deliverables:**
- [ ] Test suite with >90% coverage
- [ ] Fuzzing harnesses
- [ ] Security test scenarios

---

### 5.2 Security Documentation (4 hours)

**Create:**
1. `docs/THREAT_MODEL.md` - Formal threat modeling
2. `docs/DEPLOYMENT_GUIDE.md` - Production deployment
3. `docs/INCIDENT_RESPONSE.md` - Security incident handling
4. `docs/ARCHITECTURE.md` - Security architecture diagrams

**Content:**
- Threat actors and capabilities
- Security boundaries
- Trust assumptions
- Attack scenarios
- Mitigation strategies

**Deliverables:**
- [ ] Complete documentation set
- [ ] Deployment checklist
- [ ] Runbooks

---

### 5.3 Penetration Testing Preparation (2 hours)

**Create:** `docs/PENTEST_SCOPE.md`

**Define:**
- In-scope targets
- Out-of-scope areas
- Rules of engagement
- Reporting requirements
- Remediation timeline

**Deliverables:**
- [ ] Pentest scope document
- [ ] Test environment setup
- [ ] Contact information

---

## Implementation Schedule

### Sprint 1 (Week 1): Foundation
- **Days 1-2:** Phase 0.1 - Memory security framework
- **Days 3-4:** Phase 0.2 - Encrypted metadata design
- **Day 5:** Review and testing

**Output:** Secure foundation for all future work

---

### Sprint 2 (Week 2): Critical Fixes Part 1
- **Days 1-2:** Phase 1.1 - Encrypted metadata implementation
- **Days 3-5:** Phase 1.2 - HMAC receipt authentication

**Output:** Metadata protected, receipt authentication working

---

### Sprint 3 (Week 3): Critical Fixes Part 2
- **Days 1-2:** Phase 1.3 - Memory zeroing
- **Days 3-4:** Phase 1.4 - CSRF protection
- **Day 5:** Integration testing

**Output:** All CRITICAL issues resolved

---

### Sprint 4 (Week 4): High Priority Hardening
- **Days 1-2:** Phase 2.1 - Key management
- **Day 3:** Phase 2.2 - Secure deletion
- **Day 4:** Phase 2.3 - Header hardening
- **Day 5:** Phase 2.4 + 2.5 - Quotas and AAD

**Output:** All HIGH issues resolved

---

### Sprint 5 (Week 5): Medium Priority & Testing
- **Days 1-2:** Phase 3 (all medium priority)
- **Days 3-5:** Phase 5.1 - Comprehensive testing

**Output:** MEDIUM issues resolved, test coverage >90%

---

### Sprint 6 (Week 6): Operational & Documentation
- **Days 1-2:** Phase 4 (operational improvements)
- **Days 3-5:** Phase 5.2 + 5.3 - Documentation and pentest prep

**Output:** Production-ready system with complete documentation

---

## Testing Strategy

### Per-Phase Testing

**After Each Phase:**
1. Unit tests for new code
2. Integration tests for changed flows
3. Regression tests for existing functionality
4. Security-specific tests for addressed vulnerabilities

### Continuous Testing

**Throughout Development:**
- Run test suite on every commit
- Memory profiling for crypto operations
- Static analysis (gosec, staticcheck)
- Dependency vulnerability scanning

### Final Validation

**Before Production:**
1. Full security test suite
2. Load testing (stress test rate limits)
3. Forensic validation (secure deletion works)
4. External penetration test
5. Security audit by third party

---

## Risk Management

### High-Risk Changes

**Breaking Changes:**
1. Receipt authentication (Phase 1.2)
   - **Mitigation:** Version API, support both old/new for transition period

2. Encrypted metadata (Phase 1.1)
   - **Mitigation:** Auto-migration on read, keep backups

3. Filename randomization (Phase 3.1)
   - **Mitigation:** Receipt includes original filename hash for verification

### Rollback Strategy

**For Each Phase:**
1. Tag release before starting
2. Keep feature flags for new functionality
3. Document rollback procedure
4. Maintain backward compatibility where possible

### Monitoring During Rollout

**Track:**
- Error rates
- Upload/download success rates
- Receipt validation failures
- Rate limit triggers
- Storage quota hits

---

## Success Criteria

### Phase 0 Success
- [ ] Memory profiling shows no plaintext leaks
- [ ] Encrypted metadata format validated
- [ ] All tests passing

### Phase 1 Success
- [ ] All CRITICAL issues marked as FIXED in audit
- [ ] Receipt authentication working end-to-end
- [ ] Metadata encrypted on disk
- [ ] Memory zeroed after crypto operations
- [ ] CSRF protection tested and working

### Phase 2 Success
- [ ] All HIGH issues marked as FIXED
- [ ] Key management system operational
- [ ] Secure deletion verified forensically
- [ ] Headers hardened and tested
- [ ] Quotas enforced correctly

### Phase 3 Success
- [ ] All MEDIUM issues addressed
- [ ] File integrity verification working
- [ ] Honeypots detecting probes
- [ ] Race conditions eliminated

### Overall Success
- [ ] Security audit updated: Risk level = MODERATE
- [ ] Test coverage >90%
- [ ] All documentation complete
- [ ] Penetration test completed with no critical findings
- [ ] Production deployment successful

---

## Resource Requirements

### Development
- 1 senior security engineer (full-time, 6 weeks)
- Code review from crypto expert (consultative)
- Access to test environment with Tor

### Testing
- Penetration testing firm (1 week engagement)
- Forensic analysis tools
- Memory profiling tools
- Load testing infrastructure

### Documentation
- Technical writer (part-time, 2 weeks)
- Security documentation review

---

## Cost-Benefit Analysis

### Cost of Implementation
- Development time: 60-80 hours ($12K-$16K at $200/hr)
- Testing: 40 hours ($8K)
- Pentest: $15K-$25K
- **Total: $35K-$49K**

### Cost of NOT Implementing
- Data breach: Submitter identities exposed
- Legal liability: Failure to protect sources
- Reputation damage: Project shutdown
- **Estimated risk: $500K-$2M+**

**ROI:** 10-40x risk reduction for ~$40K investment

---

## Conclusion

This phased approach provides:
1. **Clear priorities** - Critical issues first
2. **Manageable chunks** - Weekly sprint goals
3. **Testable milestones** - Each phase independently validated
4. **Rollback safety** - Feature flags and versioning
5. **Complete coverage** - All 32 vulnerabilities addressed

**Recommended Start Date:** Immediate
**Target Completion:** 6 weeks
**Final Audit:** Week 7
**Production Ready:** Week 8

---

## Appendix A: Dependency Graph

```
Phase 0.1 (Memory Security)
    ├─> Phase 1.3 (Memory Zeroing)
    ├─> Phase 2.1 (Key Management)
    └─> All crypto operations

Phase 0.2 (Encrypted Metadata)
    ├─> Phase 1.1 (Metadata Implementation)
    └─> Phase 1.2 (HMAC Receipts)

Phase 1.2 (HMAC Receipts)
    └─> Phase 2.5 (AAD in GCM)

Phase 1.1 (Encrypted Metadata)
    └─> Phase 3.1 (Filename Randomization)
```

**Critical Path:** 0.1 → 0.2 → 1.1 → 1.2 → 1.3 → 1.4

---

## Appendix B: Quick Wins (High Impact, Low Effort)

If time is constrained, prioritize these:

1. **CSRF Protection** (5 hours) - Phase 1.4
2. **Header Hardening** (3 hours) - Phase 2.3
3. **Secure Deletion** (4 hours) - Phase 2.2
4. **File Integrity** (3 hours) - Phase 3.3
5. **Build Hardening** (1 hour) - Phase 4.1

**Total: 16 hours for 5 significant improvements**

---

**End of Remediation Plan**
