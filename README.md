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
server is required. On first start it creates `.admin-credentials.toml` with
mode `0600`, username `admin`, and a random password printed once to stdout:

```sh
target/release/sing-box-ser-mini \
  --config config.toml \
  --admin-listen 127.0.0.1:9080
```

Reset the WebUI password without starting the server:

```sh
target/release/sing-box-ser-mini \
  --admin-credentials-file .admin-credentials.toml \
  --admin-username admin \
  --reset-admin-password
```

The new password takes effect immediately because API authentication reads the
credential file on each request.

The **Management accounts** section can add multiple WebUI users, change each
password independently, and remove users while preventing deletion of the last
administrator. Existing single-user credential files are migrated to the
multi-user `[[users]]` format on the first account change. The reset command
updates or creates only the user selected by `--admin-username` and preserves
all other accounts.

The runtime uses up to four Tokio worker threads by default. Override this for
larger hosts with `--worker-threads N` after measuring the actual workload.

For external access, use the managed launcher:

```sh
CONFIG_PATH=/workspace/sing-box-ser-mini/config.toml \
  scripts/start-managed.sh
```

Open `http://server-address:9080` and sign in as `admin` with the generated
password.
The UI provides runtime status, typed configuration editing, atomic saves, and
HY2 service reloads without restarting the management process.
The listener is configured as a port in the WebUI and saved as `[::]:<port>`;
the UDP socket explicitly enables dual-stack mode so the same port accepts
both IPv4 and IPv6 traffic.
For a NAT deployment, keep the internal listener port set to the local UDP
destination and set the independent public port to the external UDP mapping.
Generated HY2 URIs and subscriptions use the public port while the server keeps
binding the internal listener port.

The service page also detects OpenRC or systemd and can install or remove the
`sing-box-ser-mini` boot service from the WebUI. The generated service preserves
the current executable, working directory, configuration, credential file,
management listen address, optional token file, runtime user, and worker count.
Installation uses root directly or a non-interactive `doas`/`sudo` policy; it
enables or removes the boot service without restarting the running process.

The outbound network section detects IPv4 and IPv6 connectivity separately and
selects the automatic policy by default. Automatic mode tries IPv4 destinations
first with IPv6 fallback; the WebUI also allows an explicit IPv4-only or
IPv6-only override and disables choices that are currently unavailable. A host
with public IPv6 ingress and a working IPv4 exit therefore accepts clients over
IPv6 while forwarding website traffic over IPv4 without setup. An IPv6-only
host shows a warning because IPv4-only websites require an external translation
service.

## Subscription converter

The WebUI includes a Rust-native subscription converter on the same management
port. It accepts SS, VMess, VLESS, Trojan, Hysteria2, TUIC, AnyTLS, and Base64
subscriptions, and emits Sing-Box, Clash, Surge, or Xray output. Generated
converter links use a bounded persisted store with a default capacity of 512
and a 24-hour TTL.

The public client routes are `/singbox`, `/clash`, `/surge`, `/xray`,
`/shorten-v2`, `/resolve`, and `/{b,c,s,x}/<code>`. Converter links are stored
with their TTL so they survive process restarts while remaining bounded by the
configured capacity. Remote HTTP(S) subscription fetching is intentionally
disabled.

The converter implements the upstream Sublink Worker rule presets (`minimal`,
`balanced`, and `comprehensive`) plus a `china` preset and an independent
ad-block option. The China preset keeps private networks and mainland services
direct, sends explicitly blocked or overseas services through the proxy, and
uses split DNS for modern Mihomo and Sing-Box clients. Adaptive short links
retain the selected preset and emit native remote rule sets for Sing-Box,
Clash/Mihomo, and Surge. Xray output remains a Base64 node subscription because
that format has no routing-policy container.

Adaptive user subscriptions recognize Sing-Box/SFA/SFI/SFM, Mihomo and modern
Clash clients (including Verge Rev, Meta for Android, FlClash, Nyanpasu,
Mihomo Party, ClashMi, Stash, Sparkle, and Surfboard), Surge, and universal
URI clients such as Xray/V2Ray, Shadowrocket, Quantumult X, Loon, NekoBox,
Hiddify, Karing, and Streisand. Unknown clients receive the broadly compatible
Base64 URI subscription. Legacy Clash clients receive YAML rule providers
instead of unsupported MRS files. Add `?format=clash`, `?format=singbox`,
`?format=surge`, or `?format=xray` to an adaptive `/sub/<code>` URL when a
client does not send an identifiable User-Agent. Subscription responses use
the first node name (the HY2 username for generated user links) as the profile
title and download filename. User IPv4/IPv6 links are permanent; only
converter-workspace links use the 24-hour persisted TTL.

The conversion behavior was rewritten in Rust from the MIT-licensed
`Amamiyashi0n/sublink-worker-c` implementation; no C code, darkhttpd process,
or secondary HTTP port is included.

Add optional sharing metadata to generate one standards-compliant Hysteria 2
URI per configured user:

```toml
[share]
server = "hy2.example.com"
# Optional independent IPv6 subscription endpoint:
# ipv6_server = "2001:db8::10"
port = 443
sni = "hy2.example.com"
insecure = false
rule_preset = "china" # china, minimal, balanced, or comprehensive
ad_block = false
whitelist = ["example.cn", "*.internal.example.cn"] # forced DIRECT
blacklist = ["ads.example.com"] # forced REJECT; evaluated before whitelist
```

Custom whitelist and blacklist entries accept exact domains and suffixes in
`*.example.com` or `.example.com` form. They are stored in permanent user
subscriptions and 24-hour converter links. Blacklist rules are evaluated first,
so a domain present in both lists is rejected.

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
