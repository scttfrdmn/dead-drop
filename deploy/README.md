# Deployment Examples

Ephemeral logging configurations for Dead Drop. Logs are written to tmpfs-backed storage that exists only in RAM and is destroyed on reboot or container stop.

## Docker Compose

The `docker-compose.yml` mounts a tmpfs volume at `/var/log/dead-drop` (64 MB, mode 0700). Logs never touch disk.

```bash
# Start with ephemeral logs
docker compose up -d

# View logs while running
docker compose exec dead-drop cat /var/log/dead-drop/dead-drop.log

# Logs are gone after stop
docker compose down
```

## systemd

The `dead-drop.service` unit uses `LogsDirectory=dead-drop` to create `/var/log/dead-drop` owned by the service user.

To make logs ephemeral, mount `/var/log/dead-drop` as tmpfs:

```bash
# Add to /etc/fstab
tmpfs /var/log/dead-drop tmpfs size=64M,mode=0700,uid=dead-drop,gid=dead-drop 0 0

# Or mount immediately
sudo mount -t tmpfs -o size=64M,mode=0700,uid=dead-drop,gid=dead-drop tmpfs /var/log/dead-drop
```

Then install and start the service:

```bash
sudo cp dead-drop.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dead-drop
```

## Manual

Use the `-log-dir` flag or `log_dir` config option to point logs at any tmpfs mount:

```bash
# Create a tmpfs mount
sudo mkdir -p /mnt/ephemeral-logs
sudo mount -t tmpfs -o size=64M tmpfs /mnt/ephemeral-logs

# Run with ephemeral logs
dead-drop-server -config config.yaml -log-dir /mnt/ephemeral-logs
```
