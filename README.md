# proxy-mcp

**MCP server** for AI agents to run a local HTTPS MITM proxy and mock headend/backend responses on real Android devices — at the network level, with zero app source changes.

- Intercepts HTTP/HTTPS traffic from physical devices and emulators
- Registers mock responses and JSON transform rules via MCP tools
- Probes transforms before registering (one-shot dry-run patch)
- Persists/restores transform rules across proxy restarts
- Tracks per-request transform outcomes — distinguish patched, no_match, error
- Gzip-safe — transparently decompresses, patches, and recompresses
- CLI fallback when MCP is unavailable

## Charles-only CA

This proxy **must** use the same CA certificate that the target app's `network_security_config.xml` trusts. The only supported path is the **Charles Proxy CA** — no auto-generation, no Frida, no alternative CAs.

## Requirements

- Node >= 24
- `adb` on PATH (for device proxy setup)
- Charles Proxy CA (cert + key exported from Charles)

## Setup

No clone needed. Install via npm:

```bash
npx @shahfazliz/proxy-mcp
```

### 1. Extract your Charles Proxy CA

Charles stores its CA at `~/Library/Application Support/Charles/ca/`. Extract the cert and key into your project's `.proxy-ca/` directory:

```bash
# From Charles's .p12 export
mkdir -p .proxy-ca
openssl pkcs12 -in ~/Library/Application\ Support/Charles/ca/charles-ssl-proxying.p12 \
  -nocerts -nodes -out .proxy-ca/key.pem
openssl pkcs12 -in ~/Library/Application\ Support/Charles/ca/charles-ssl-proxying.p12 \
  -clcerts -nokeys -out .proxy-ca/cert.pem

# Or use the built-in CLI
npx proxy-mcp-cli ca:import --p12 ~/Library/Application\ Support/Charles/ca/charles-ssl-proxying.p12
```

Both files must be clean PEM (no Bag Attributes, no PKCS12 wrapping).

### 2. Register with Cursor / any MCP client

```json
{
  "mcpServers": {
    "shah-proxy": {
      "command": "npx",
      "args": [
        "-y",
        "git+https://github.com/shahfazliz/proxy-mcp",
        "--ca-dir",
        "/absolute/path/to/.proxy-ca"
      ],
      "enabled": true
    }
  }
}
```

The `--ca-dir` must point to a directory containing `cert.pem` and `key.pem` (see step 1). This is typically your Charles CA directory at `~/Library/Application Support/Charles/ca/` or an extracted `.proxy-ca/` folder in your project.

## Quick start

```bash
# 1. Start proxy (port 8889, Metro dev server passthrough)
proxy_start --passthroughHosts '["localhost:8081"]'

# 2. Point device at the proxy
adb -e shell settings put global http_proxy 10.0.2.2:8889    # emulator
adb -s <ip> shell settings put global http_proxy <lan>:8889   # physical

# 3. Probe a transform before registering (dry-run)
proxy_probe_transform --url https://api.example.com/items \
  --patches '[{ "path": "items[]", "set": { "endTime": "__NOW_PLUS_2M__" } }]'

# 4. Register the transform
proxy_update_transform --method GET --url viewMultiviews \
  --patches '[{ "path": "items[]", "where": { "isMultiview": true }, "set": { "endTime": "__NOW_PLUS_2M__" } }]'

# 5. Traffic observability — check transform outcomes per request
proxy_list_traffic --filter viewMultiviews

# 6. Clean up
adb -e shell settings put global http_proxy :0
proxy_stop
```

## MCP tools (~15)

| Tool | Purpose |
|------|---------|
| `proxy_start` / `proxy_stop` | Start/stop the MITM proxy |
| `proxy_health` | Running state, rule counts, captured traffic, warnings |
| `proxy_mock_response` | Static mock response for a URL pattern |
| `proxy_mock_transform` | JSON transform rule for a URL pattern |
| `proxy_update_transform` | Idempotent upsert of a transform rule |
| `proxy_list_mocks` / `proxy_clear_mocks` | Manage mock responses |
| `proxy_list_transforms` / `proxy_clear_transforms` | Manage transform rules |
| `proxy_list_traffic` | Captured requests with transform outcomes |
| `proxy_probe_transform` | One-shot fetch + dry-run patch, returns before/after |
| `proxy_save_transforms` / `proxy_load_transforms` | Persist/restore to JSON file |
| `proxy_ca_info` | SHA-256 fingerprint, setup instructions |

See the [wiki](./wiki/tools.md) for full parameter docs.

## App dependency

Your debug APK must trust the proxy's CA. For an Android TV app:

- Set `enableSystemProxy=true` in `apps/tv/android/gradle.properties`
- This bakes the CA cert into the APK via `res/raw/cacert`
- Verify the fingerprint from `proxy_ca_info` matches the app's bundled cert

No device-side CA installation, no root, no Magisk needed — trust is app-bundled.

## CLI fallback

```bash
npx proxy-mcp-cli start --port 8889
npx proxy-mcp-cli status
npx proxy-mcp-cli ca-info
npx proxy-mcp-cli ca:import --p12 /path/to/charles-ssl-proxying.p12
npx proxy-mcp-cli transform add GET "https://..." patches.json
npx proxy-mcp-cli traffic --filter example
```

## Metro passthrough

The proxy automatically forwards Metro bundler requests (`:8081`) to the local dev server. Headers like `newrelic`, `traceparent`, `tracestate`, and `accept-encoding` are stripped from forwarded Metro requests to avoid breaking the bundler.

## Git-ignored (keep local)

- `.proxy-ca/` — CA private key + cert
- `transforms.json` — auto-saved on proxy stop
- `traffic-*.json` / `*.har` — exported traffic logs
- `*.p12`, `cacert.pem` — raw Charles exports

## License

UNLICENSED — internal tool. Not distributed publicly.
