# Key Management

This document describes the cryptographic key hierarchy, key lifecycle, rotation procedures, and emergency recovery for Dead Drop.

## Key Hierarchy

```
Master Passphrase (human-memorized or secrets manager)
  │
  ▼
Argon2id(time=3, mem=64MB, threads=4, salt=.master.salt)
  │
  ▼
Master Key (32 bytes, derived in memory, never stored)
  │
  ├──► Wraps .encryption.key (AES-256-GCM)
  │         │
  │         ├──► Encrypts drop files (AES-256-GCM, AAD=dropID)
  │         │
  │         └──► HKDF-SHA256("dead-drop-metadata-" + dropID)
  │                   │
  │                   └──► Per-drop metadata key (32 bytes)
  │                             │
  │                             └──► Encrypts drop metadata (AES-256-GCM)
  │
  └──► Wraps .receipt.key (AES-256-GCM)
            │
            └──► HMAC-SHA256(receipt_key, dropID) → receipt token
```

## Key Types

| Key | File | Size | Format | Purpose |
|-----|------|------|--------|---------|
| Master passphrase | Not stored | Variable | UTF-8 string | Input to Argon2id derivation |
| Master key | In memory only | 32 bytes | Raw | Wraps/unwraps key files |
| Argon2id salt | `.master.salt` | 16 bytes | Raw | Unique per installation |
| Encryption key | `.encryption.key` | 32 bytes (plain) or 60 bytes (encrypted) | Raw or nonce+ciphertext+tag | Encrypts/decrypts drop data |
| Receipt key | `.receipt.key` | 32 bytes (plain) or 60 bytes (encrypted) | Raw or nonce+ciphertext+tag | HMAC secret for receipt generation |
| Per-drop metadata key | Derived, not stored | 32 bytes | Raw (in memory) | Encrypts drop metadata |

**Encrypted key file format (60 bytes):**
```
┌──────────┬────────────────────┬──────────┐
│ Nonce    │ Encrypted Key      │ GCM Tag  │
│ 12 bytes │ 32 bytes           │ 16 bytes │
└──────────┴────────────────────┴──────────┘
```

## Initial Setup

### Without Master Key

On first run without `master_key_env` configured:

1. Server generates a random 32-byte encryption key → `.encryption.key`
2. Server generates a random 32-byte receipt key → `.receipt.key`
3. Keys are stored as plaintext (32 bytes each)

### With Master Key

On first run with `master_key_env` configured:

1. Server reads the passphrase from the named environment variable
2. Generates a 16-byte random salt → `.master.salt`
3. Derives the master key: `Argon2id(passphrase, salt, time=3, mem=64MB, threads=4) → 32 bytes`
4. Generates random encryption and receipt keys
5. Wraps both keys with the master key using AES-256-GCM → 60-byte encrypted files

### Auto-Migration

If `master_key_env` is added to an existing installation with plaintext keys:

1. Server detects plaintext keys (32-byte files)
2. Reads and decrypts them in memory
3. Generates `.master.salt` if missing
4. Re-writes both key files in encrypted format (60 bytes)

This is automatic and transparent. No data re-encryption is needed; only the key files change format.

## Key Rotation Procedures

The `dead-drop-rotate-keys` utility supports two modes.

### Password-Only Change (Rewrap)

Changes the master key passphrase without re-encrypting drop data. Use this when the passphrase may have been exposed but the encryption keys themselves are not compromised.

```bash
export DEAD_DROP_OLD_MASTER_KEY="current-passphrase"
export DEAD_DROP_MASTER_KEY="new-passphrase"

dead-drop-rotate-keys \
  -storage-dir /var/lib/dead-drop/drops \
  -rewrap-only
```

This operation:
- Decrypts `.encryption.key` and `.receipt.key` with the old master key
- Generates a new salt (`.master.salt`)
- Derives a new master key from the new passphrase
- Re-wraps both key files with the new master key
- Does **not** touch any drop data files

**Duration:** Near-instant regardless of drop count.

### Full Key Rotation

Generates a new encryption key and re-encrypts all drops. Use this when the encryption key itself may be compromised.

```bash
export DEAD_DROP_OLD_MASTER_KEY="current-passphrase"
export DEAD_DROP_MASTER_KEY="new-passphrase"

dead-drop-rotate-keys \
  -storage-dir /var/lib/dead-drop/drops
```

This operation:
- Decrypts the old encryption key with the old master key
- Generates a new random 32-byte encryption key
- Re-encrypts every drop's `data` file with the new key
- Re-encrypts every drop's `meta` file with a new HKDF-derived key
- Re-wraps the receipt key with the new master key
- Generates a new salt and wraps the new encryption key

**Duration:** Proportional to the number and size of stored drops.

**Important:** Stop the server before running full rotation to prevent concurrent access:
```bash
sudo systemctl stop dead-drop
dead-drop-rotate-keys -storage-dir /var/lib/dead-drop/drops
sudo systemctl start dead-drop
```

### Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `DEAD_DROP_OLD_MASTER_KEY` | If keys are currently encrypted | Current master key passphrase |
| `DEAD_DROP_MASTER_KEY` | Always | New master key passphrase |

If keys are currently plaintext (no master key configured), omit `DEAD_DROP_OLD_MASTER_KEY`.

## Secure Receipt Exchange

Receipts (64-char hex HMAC tokens) must be shared through a secure out-of-band channel. The receipt is the only authorization required to retrieve a drop.

### Using GPG/PGP

```bash
# Encrypt receipt for the recipient
echo "Drop ID: <id>" | gpg --encrypt --recipient recipient@example.com --armor

# Recipient decrypts
gpg --decrypt message.asc
```

### Using age

```bash
# Encrypt with recipient's public key
echo "Drop ID: <id>, Receipt: <receipt>" | age -r age1... > receipt.age

# Recipient decrypts
age --decrypt -i key.txt receipt.age
```

### Using Signal

Send the drop ID and receipt as a disappearing message in Signal. Enable disappearing messages with a short timer (e.g., 5 minutes).

### Security Considerations

- Never transmit receipts over unencrypted channels (email, SMS, HTTP)
- Never include receipts in the same channel as the server's `.onion` address
- Consider splitting the drop ID and receipt across two different channels

## Multi-Party Custody

For high-security deployments, split the master passphrase using Shamir's Secret Sharing so that no single person can unlock the keys.

### Setup with `ssss-split`

```bash
# Split into 5 shares, requiring 3 to reconstruct
echo "your-master-passphrase" | ssss-split -t 3 -n 5
```

Distribute shares to 5 custodians. Any 3 can reconstruct the passphrase:

```bash
# Combine 3 shares
ssss-combine -t 3
```

### Operational Procedure

1. At server startup, 3 of 5 custodians convene
2. Each provides their share to reconstruct the passphrase
3. The passphrase is set as `DEAD_DROP_MASTER_KEY` environment variable
4. The server is started
5. The passphrase is cleared from the environment

## Emergency Procedures

### Lost Master Key Passphrase

If the master key passphrase is lost and no custodians can reconstruct it:

- **All encrypted drops are permanently unrecoverable.** There is no backdoor or recovery mechanism.
- The `.encryption.key` and `.receipt.key` files cannot be decrypted without the master key.
- A fresh installation is required with new keys.

### Compromised Encryption Key

If the `.encryption.key` contents are exposed (even briefly):

1. **Stop the server immediately**
2. Perform a **full key rotation** (not rewrap-only)
3. All drops are re-encrypted with a fresh key
4. Assume drops that existed before rotation may have been readable during the exposure window

### Compromised Receipt Key

If the `.receipt.key` contents are exposed:

1. An attacker could forge valid receipts for any drop ID
2. Perform a **full key rotation** to generate a new receipt key
3. All previously issued receipts become invalid after rotation
4. Re-issue receipts to legitimate users through secure channels

### Compromised Master Salt

The `.master.salt` alone is not sufficient to derive the master key (the passphrase is also required). However, if both salt and passphrase are compromised, treat as a full key compromise and perform full rotation.

## Related Documents

- [Architecture](ARCHITECTURE.md) - Encryption layers and data flow
- [Threat Model](THREAT_MODEL.md) - Key compromise attack scenarios
- [Incident Response](INCIDENT_RESPONSE.md) - Compromise response procedures
- [Deployment Guide](DEPLOYMENT_GUIDE.md) - Master key setup
