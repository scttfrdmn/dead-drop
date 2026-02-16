# Incident Response

This document provides procedures for detecting, responding to, and recovering from security incidents affecting a Dead Drop deployment.

## Detection Methods

### Honeypot Alerts

If honeypots are enabled, accessing a canary drop triggers:

- A log entry on the server
- An HTTP POST to the configured `alert_webhook` with:
  ```json
  {
    "event": "honeypot_access",
    "drop_id": "<32-char-hex>",
    "timestamp": "2026-01-15T12:00:00Z",
    "remote_addr": "127.0.0.1:12345"
  }
  ```

Any honeypot access indicates unauthorized knowledge of drop IDs and should be investigated immediately.

### Metrics Anomalies

If Prometheus monitoring is configured, watch for:

- Sudden spike in retrieval attempts (potential enumeration)
- Elevated rate-limit rejections (potential brute-force)
- Unusual upload/download volume patterns
- Storage quota approaching limits unexpectedly

### Log Monitoring

With `logging.errors: true`, monitor for:

- Repeated authentication failures (invalid receipts)
- File decryption errors (potential ciphertext tampering)
- Rate limit violations from concentrated IP ranges
- Unexpected server restarts or crashes

### External Indicators

- Unauthorized access to the server host (SSH logs, audit logs)
- Network traffic anomalies from IDS/IPS systems
- Unexpected modifications to key files or configuration

## Severity Levels

### P1 - Critical: Key Compromise or Server Breach

**Indicators:**
- Master key, `.encryption.key`, or `.receipt.key` exposed
- Unauthorized root/user access to the server
- Evidence of file exfiltration from the storage directory
- `.master.salt` or key files modified unexpectedly

**Response time:** Immediate (within minutes)

### P2 - High: Unauthorized Access Attempt

**Indicators:**
- Honeypot access alert triggered
- Sustained brute-force attempts against drop IDs
- Valid receipt used from an unexpected source
- Attempted path traversal or injection in requests

**Response time:** Within 1 hour

### P3 - Medium: Denial of Service or Enumeration

**Indicators:**
- Rate limiter triggered persistently from multiple IPs
- Storage quota exhausted by malicious uploads
- Server performance degradation under load

**Response time:** Within 4 hours

## Response Procedures

### P1: Key Compromise

If encryption keys or the master key passphrase are compromised:

**Step 1: Take the server offline immediately**

```bash
sudo systemctl stop dead-drop
```

**Step 2: Preserve evidence**

Copy the entire storage directory, logs, and key files before making any changes:

```bash
sudo cp -a /var/lib/dead-drop/drops /var/lib/dead-drop/drops.evidence.$(date +%s)
sudo cp -a /var/log/dead-drop /var/log/dead-drop.evidence.$(date +%s)
```

Preserve the `.master.salt` file:
```bash
sudo cp /var/lib/dead-drop/drops/.master.salt /root/evidence/
```

**Step 3: Perform full key rotation**

A full rotation generates new encryption keys and re-encrypts all drops:

```bash
export DEAD_DROP_OLD_MASTER_KEY="old-passphrase"
export DEAD_DROP_MASTER_KEY="new-strong-passphrase"
dead-drop-rotate-keys -storage-dir /var/lib/dead-drop/drops
```

Do **not** use `-rewrap-only` when keys are compromised. Full rotation re-encrypts all drop data and metadata with fresh keys.

**Step 4: Re-derive master key**

The full rotation already creates a new salt and re-wraps keys. Verify:

```bash
ls -la /var/lib/dead-drop/drops/.master.salt
ls -la /var/lib/dead-drop/drops/.encryption.key
ls -la /var/lib/dead-drop/drops/.receipt.key
```

Key files should be 60 bytes (encrypted format).

**Step 5: Notify affected parties**

Assume all drops stored at the time of compromise may have been accessed. Notify submitters through the same secure channel used for receipt exchange.

**Step 6: Restart the server**

```bash
sudo systemctl start dead-drop
```

### P1: Server Compromise

If the server host itself is compromised:

**Step 1: Assume all drops are compromised**

A compromised server with access to process memory could have decrypted keys in memory, even if encrypted at rest.

**Step 2: Create a forensic image**

Before wiping, capture a disk image for investigation:

```bash
sudo dd if=/dev/sda of=/mnt/external/forensic-image.img bs=4M status=progress
```

**Step 3: Wipe and reinstall**

Perform a clean OS installation. Do not attempt to "clean" a compromised system.

**Step 4: Deploy fresh**

1. Install Dead Drop from a verified source
2. Use `make build-production` on a trusted build machine
3. Generate new keys (do not reuse old key material)
4. Configure with a new master key passphrase
5. Apply all hardening from the [Deployment Guide](DEPLOYMENT_GUIDE.md)

**Step 5: Notify all parties**

All prior drop contents should be considered compromised. Previous receipts are invalidated (new receipt key).

### P2: Honeypot Access

**Step 1: Log the alert details**

Record the `drop_id`, `timestamp`, and `remote_addr` from the webhook.

**Step 2: Analyze access patterns**

Determine if this was:
- A random brute-force hit (unlikely given 128-bit ID space)
- Evidence of leaked drop IDs
- An insider with knowledge of honeypot IDs

**Step 3: Review access logs (if enabled)**

If `logging.operations: true`, check for other access from the same source.

**Step 4: Consider rotating honeypots**

If honeypot IDs may be known, restart the server with new honeypots:

```bash
# Remove old honeypot list
sudo rm /var/lib/dead-drop/drops/.honeypots
# Restart to regenerate
sudo systemctl restart dead-drop
```

**Step 5: Escalate if pattern indicates compromise**

If honeypot access suggests insider knowledge or server breach, escalate to P1.

### P3: Denial of Service

**Step 1: Identify attack pattern**

Review rate limiter rejections and source IPs.

**Step 2: Tighten rate limits temporarily**

```yaml
security:
  rate_limit_per_min: 5
```

**Step 3: Add firewall rules**

Block offending IPs or ranges at the network level:

```bash
sudo iptables -A INPUT -s <attacker-ip> -j DROP
```

**Step 4: Verify quota protections**

Ensure `max_storage_gb` and `max_drops` are configured to prevent storage exhaustion.

## Recovery Procedures

### Clean State Recovery

When recovering from a P1 incident with a fresh installation:

1. Install a clean OS on verified hardware
2. Build Dead Drop from source: `make build-production`
3. Create a new configuration file (do not reuse compromised config)
4. Set a new master key passphrase
5. Start the server (generates fresh keys and salt)
6. Re-enable honeypots and monitoring
7. Verify all hardening checklist items from [Deployment Guide](DEPLOYMENT_GUIDE.md)

### Key-Only Recovery

When only key material was exposed (server integrity is intact):

1. Stop the server
2. Run full key rotation (see P1 Key Compromise above)
3. Update the master key passphrase
4. Restart and verify

## Post-Incident Review

After resolving any P1 or P2 incident, conduct a review:

- [ ] Document timeline of events (detection, response, resolution)
- [ ] Identify root cause of the incident
- [ ] Assess what data may have been exposed
- [ ] Determine if detection was timely; improve monitoring if not
- [ ] Review and update access controls
- [ ] Verify all key material has been rotated
- [ ] Update this incident response plan with lessons learned
- [ ] Archive forensic evidence securely

## Contact and Escalation Template

```
INCIDENT REPORT
===============
Date/Time Detected:
Severity: P1 / P2 / P3
Detected By: (honeypot alert / monitoring / manual discovery)

Summary:
(Brief description of what happened)

Affected Systems:
- Server: (hostname/IP)
- Storage: (path)
- Estimated drops affected: (count or "all")

Actions Taken:
1.
2.
3.

Current Status: (contained / investigating / resolved)

Next Steps:
1.
2.

Responder:
Contact:
```

## Related Documents

- [Threat Model](THREAT_MODEL.md) - Attack scenarios this plan addresses
- [Key Management](KEY_MANAGEMENT.md) - Key rotation procedures
- [Deployment Guide](DEPLOYMENT_GUIDE.md) - Hardening checklist
- [Architecture](ARCHITECTURE.md) - System internals
