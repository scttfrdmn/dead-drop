# Tor Hidden Service Setup for Dead Drop

This guide covers running dead-drop as a Tor hidden service so it is only accessible via its `.onion` address.

## Prerequisites

- Tor installed (`apt install tor` on Debian/Ubuntu, `brew install tor` on macOS)
- dead-drop server binary built (`make build`)

## 1. Configure Tor

Edit your `torrc` file (typically `/etc/tor/torrc`):

```
HiddenServiceDir /var/lib/tor/dead-drop/
HiddenServicePort 80 127.0.0.1:8080
```

This tells Tor to:
- Create a hidden service identity in `/var/lib/tor/dead-drop/`
- Forward incoming connections on virtual port 80 to dead-drop on `127.0.0.1:8080`

Restart Tor:

```bash
sudo systemctl restart tor
```

Your `.onion` address will be in `/var/lib/tor/dead-drop/hostname`:

```bash
sudo cat /var/lib/tor/dead-drop/hostname
```

## 2. Configure Dead Drop

In your `config.yaml`, enable Tor-only mode:

```yaml
server:
  listen: "127.0.0.1:8080"

security:
  tor_only: true
```

With `tor_only: true`:
- Only connections from loopback addresses (`127.0.0.1` / `::1`) are accepted
- All other connections receive a `403 Forbidden` response
- If the listen address binds all interfaces (e.g., `:8080`), it is automatically overridden to `127.0.0.1:8080`

Alternatively, enable via CLI flag:

```bash
./dead-drop-server -config config.yaml -tor-only
```

## 3. Start the Server

```bash
./dead-drop-server -config config.yaml
```

## 4. Verify

From the same machine, confirm the server responds on localhost:

```bash
curl http://127.0.0.1:8080/
```

From a remote machine (or a different interface), confirm the connection is refused or blocked:

```bash
# This should fail — the server only listens on 127.0.0.1
curl http://<server-ip>:8080/
```

Test access via Tor using the CLI tool:

```bash
./dead-drop-cli -tor -server http://<your-onion-address>.onion submit testfile.txt
```

## Security Notes

- **Do not expose port 8080 externally.** The default listen address `127.0.0.1:8080` ensures this, but verify firewall rules as well.
- **TLS is not required** when running as a Tor hidden service — Tor provides end-to-end encryption between the client and the hidden service.
- **Enable `delete_after_retrieve: true`** for true dead-drop behavior where files are destroyed after a single retrieval.
