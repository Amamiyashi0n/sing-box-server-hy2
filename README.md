# sing-box-ser-mini

Rust reimplementation of the sing-box Hysteria 2 inbound server only.

Scope:

- Hysteria 2 inbound server over QUIC and TLS.
- Password authentication, TCP relay, and UDP relay.
- No Hysteria 2 outbound client or other sing-box protocols.

Implemented:

- QUIC/TLS HTTP/3 authentication with multiple password users.
- Byte-compatible HY2 TCP and UDP framing.
- TCP forwarding and UDP sessions with fragmentation, reassembly, and idle cleanup.
- Salamander UDP obfuscation.
- HY2 bandwidth negotiation with dynamic BBR/Brutal congestion control.
- String, directory, and reverse-proxy HTTP/3 masquerade handlers.

Start the server inside the development container:

```sh
cd /workspace/sing-box-ser-mini
cargo run --release -- --config config.example.toml
```

## WebUI

The Rust process serves the management UI and API directly; no separate HTTP
server is required. Loopback access does not require a token:

```sh
target/release/sing-box-ser-mini \
  --config config.toml \
  --admin-listen 127.0.0.1:9080
```

The runtime uses up to four Tokio worker threads by default. Override this for
larger hosts with `--worker-threads N` after measuring the actual workload.

For external access, use the managed launcher. It creates `.admin-token` with
mode `0600` and refuses public management access without a token:

```sh
CONFIG_PATH=/workspace/sing-box-ser-mini/config.toml \
  scripts/start-managed.sh
```

Open `http://server-address:9080` and enter the value from `.admin-token`.
The UI provides runtime status, typed configuration editing, atomic saves, and
HY2 service reloads without restarting the management process.

Add optional sharing metadata to generate one standards-compliant Hysteria 2
URI per configured user:

```toml
[share]
server = "hy2.example.com"
port = 443
sni = "hy2.example.com"
insecure = false
```

The generated URI includes authentication, TLS, and Salamander parameters, but
intentionally excludes client-specific bandwidth settings.

Masquerade is optional and defaults to an empty 404 response. The supported
TOML forms are:

```toml
[masquerade]
type = "string"
status_code = 200
content = "hello"
headers = { content-type = ["text/plain"] }

# Or serve a directory:
# [masquerade]
# type = "file"
# directory = "/var/www"

# Or forward requests to HTTP/HTTPS:
# [masquerade]
# type = "proxy"
# url = "http://127.0.0.1:8080"
# rewrite_host = true
```

`reference/sing-quic` is a read-only upstream reference pinned to the version
used by the adjacent sing-box checkout. The server entry point is
`reference/sing-quic/hysteria2/service.go`.

`examples/h3_probe.rs` is an integration probe for the masquerade-to-auth flow.
The official sing-box client test configurations are under `integration/`.
Generate the disposable localhost certificate before running them:

```sh
integration/generate-cert.sh
```
