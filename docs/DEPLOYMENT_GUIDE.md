# Deployment Guide

This guide covers building, configuring, and hardening Dead Drop for production deployment.

## Prerequisites

- **Go 1.22+** (for building from source)
- **Linux** recommended (systemd support, tmpfs, Tor integration)
- **Tor** (optional, for hidden service deployment)

## Building

### Standard Build

```bash
make build
```

Produces three binaries:
- `dead-drop-server` - Main server
- `dead-drop-submit` - CLI submission tool
- `dead-drop-rotate-keys` - Key rotation utility

### Production Build

```bash
make build-production
```

Production builds include:
- `-trimpath` - Strips filesystem paths from binary
- `-ldflags="-s -w"` - Strips debug symbols and symbol table
- Embedded version string (`git describe`) and build timestamp

Always use production builds for deployment. Debug symbols and paths can leak information about your build environment.

## Deployment Options

### Tor Hidden Service (Recommended)

Running as a Tor hidden service provides the strongest anonymity guarantees. See [deploy/tor-hidden-service.md](../deploy/tor-hidden-service.md) for the full guide. Summary:

1. Install Tor and add to `/etc/tor/torrc`:
   ```
   HiddenServiceDir /var/lib/tor/dead-drop/
   HiddenServicePort 80 127.0.0.1:8080
   ```

2. Restart Tor and retrieve your `.onion` address:
   ```bash
   sudo systemctl restart tor
   sudo cat /var/lib/tor/dead-drop/hostname
   ```

3. Configure Dead Drop with Tor-only mode:
   ```yaml
   server:
     listen: "127.0.0.1:8080"
   security:
     tor_only: true
   ```

4. TLS is **not required** when running behind Tor (Tor provides end-to-end encryption).

### TLS Deployment (Non-Tor)

For clearnet deployments, always enable TLS:

```yaml
server:
  listen: "0.0.0.0:443"
  tls:
    cert_file: "/etc/dead-drop/cert.pem"
    key_file: "/etc/dead-drop/key.pem"
```

When TLS is enabled, the server automatically adds the HSTS header:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains
```

Use certificates from Let's Encrypt or your organization's CA. Self-signed certificates should only be used for testing.

## Master Key Setup

The master key encrypts `.encryption.key` and `.receipt.key` at rest using Argon2id key derivation.

1. Choose a strong passphrase and set it as an environment variable:
   ```bash
   export DEAD_DROP_MASTER_KEY="your-strong-passphrase-here"
   ```

2. Reference the variable name in your config:
   ```yaml
   security:
     master_key_env: "DEAD_DROP_MASTER_KEY"
   ```

3. On first start with `master_key_env` configured, the server:
   - Generates a 16-byte random salt (`.master.salt`)
   - Derives a master key via Argon2id (time=3, mem=64MB, threads=4)
   - Auto-migrates existing plaintext key files to encrypted format

4. On subsequent starts, the same passphrase must be provided or the server cannot decrypt its keys.

**Important:** Never store the passphrase on disk. Use a secrets manager, systemd `EnvironmentFile`, or manual entry at startup.

## Production Hardening Checklist

### 1. Enable Single-Retrieval Mode

```yaml
security:
  delete_after_retrieve: true
```

Files are securely deleted immediately after the first download.

### 2. Enable Secure Deletion

```yaml
security:
  secure_delete: true   # default
```

Files are overwritten with 3 passes (zeros, ones, random) before removal. For SSDs, also use full-disk encryption (LUKS/dm-crypt).

### 3. Set Maximum File Age

```yaml
security:
  max_age_hours: 168   # 7 days (default)
```

Drops older than this are automatically cleaned up (with +/-10 minute jitter).

### 4. Configure Storage Quotas

```yaml
security:
  max_storage_gb: 10
  max_drops: 1000
```

Prevents disk exhaustion attacks. Set values appropriate for your storage capacity.

### 5. Configure Rate Limiting

```yaml
security:
  rate_limit_per_min: 10   # default
```

Limits requests per IP per minute. Adjust based on expected traffic patterns.

### 6. Enable Honeypots

```yaml
security:
  honeypots_enabled: true
  honeypot_count: 5
  alert_webhook: "https://your-alerting-endpoint.example.com/alert"
```

Honeypots are decoy drops that trigger alerts when accessed. They are indistinguishable from real drops. The webhook receives a JSON POST with `event`, `drop_id`, `timestamp`, and `remote_addr`.

### 7. Use Ephemeral Logs

Point logs to a tmpfs mount so they exist only in RAM:

```yaml
logging:
  startup: true
  errors: true
  operations: false   # disable for anonymity
  log_dir: "/var/log/dead-drop"
```

```bash
# /etc/fstab entry
tmpfs /var/log/dead-drop tmpfs size=64M,mode=0700,uid=dead-drop,gid=dead-drop 0 0
```

### 8. Restrict Metrics to Localhost

```yaml
server:
  metrics:
    enabled: true
    localhost_only: true
```

Metrics expose operational counters (no sensitive data) in Prometheus format at `/metrics`.

### 9. Run as Unprivileged User

Create a dedicated system user:

```bash
sudo useradd -r -s /usr/sbin/nologin dead-drop
sudo mkdir -p /var/lib/dead-drop
sudo chown dead-drop:dead-drop /var/lib/dead-drop
sudo chmod 0700 /var/lib/dead-drop
```

### 10. Set Storage Directory Permissions

```bash
chmod 0700 /var/lib/dead-drop/drops
```

The server creates directories with `0700` and files with `0600` permissions.

### 11. Use Production Build Flags

Always deploy with `make build-production` to strip debug symbols and filesystem paths.

### 12. Configure Firewall Rules

For Tor deployments, only localhost should reach the server:

```bash
# Allow only loopback
sudo iptables -A INPUT -p tcp --dport 8080 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
```

For clearnet TLS deployments, restrict to the necessary port (443).

## Full Annotated Configuration

```yaml
server:
  listen: "127.0.0.1:8080"    # Bind address (loopback for Tor)
  storage_dir: "/var/lib/dead-drop/drops"  # Encrypted file storage
  max_upload_mb: 100           # Maximum upload size in MB

  # TLS (skip for Tor deployments)
  # tls:
  #   cert_file: "/etc/dead-drop/cert.pem"
  #   key_file: "/etc/dead-drop/key.pem"

  metrics:
    enabled: true              # Expose /metrics endpoint
    localhost_only: true       # Restrict to 127.0.0.1 access

security:
  delete_after_retrieve: true  # True dead-drop: one retrieval, then destroy
  max_age_hours: 168           # Auto-cleanup after 7 days
  rate_limit_per_min: 10       # Per-IP request throttle
  secure_delete: true          # 3-pass overwrite before deletion
  max_storage_gb: 10           # Disk quota
  max_drops: 1000              # Maximum concurrent drops
  master_key_env: "DEAD_DROP_MASTER_KEY"  # Env var for key encryption passphrase
  honeypots_enabled: true      # Enable canary drops
  honeypot_count: 5            # Number of decoy drops
  alert_webhook: "https://alerts.example.com/dead-drop"  # Honeypot alert endpoint
  tor_only: true               # Reject non-loopback connections

logging:
  startup: true                # Log server startup info
  errors: true                 # Log errors
  operations: false            # DISABLE for anonymity
  log_dir: "/var/log/dead-drop"  # tmpfs-backed log directory
```

## Systemd Service

Use the provided unit file at [deploy/dead-drop.service](../deploy/dead-drop.service):

```ini
[Unit]
Description=Dead Drop Anonymous File Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=dead-drop
Group=dead-drop

ExecStart=/usr/local/bin/dead-drop-server \
    -config /etc/dead-drop/config.yaml \
    -log-dir /var/log/dead-drop

LogsDirectory=dead-drop
RuntimeDirectory=dead-drop

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/dead-drop /var/log/dead-drop

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Install:

```bash
sudo cp dead-drop.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dead-drop
```

To pass the master key securely, use an `EnvironmentFile`:

```bash
# /etc/dead-drop/env (mode 0600, owned by root)
DEAD_DROP_MASTER_KEY=your-passphrase-here
```

Add to the `[Service]` section:
```ini
EnvironmentFile=/etc/dead-drop/env
```

## Monitoring

When metrics are enabled, scrape `/metrics` with Prometheus:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'dead-drop'
    static_configs:
      - targets: ['127.0.0.1:8080']
    scrape_interval: 30s
```

Metrics include operational counters only. No sensitive data (drop IDs, filenames, IP addresses) is exposed.

## Related Documents

- [Architecture](ARCHITECTURE.md) - System internals and data flow
- [Key Management](KEY_MANAGEMENT.md) - Key setup and rotation
- [Threat Model](THREAT_MODEL.md) - Security analysis
- [Incident Response](INCIDENT_RESPONSE.md) - Breach procedures
