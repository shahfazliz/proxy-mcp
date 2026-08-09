# proxy-mcp

**MCP server** for AI agents to run a local HTTPS MITM proxy and mock headend/backend responses on real Android devices — at the network level, with zero app source changes.

- Intercepts HTTP/HTTPS traffic from physical devices and emulators
- Registers mock responses and JSON transform rules via MCP tools
- Modifies outgoing requests (headers / query / body) via request-transform rules
- Probes transforms before registering (one-shot dry-run patch)
- Persists/restores transform rules across proxy restarts
- Tracks per-request transform outcomes — distinguish patched, no_match, error
- Gzip-safe — transparently decompresses, patches, and recompresses
- Rewrites passthrough hosts (e.g. Android emulator `10.0.2.2` → `127.0.0.1`)
- Simulates slow servers on mocks: `delayMs` processing time + `bandwidthKbps` streaming cap
- Capture scoping (`proxy_scope`): retain only the hosts you're investigating so the log stays small
- CLI fallback when MCP is unavailable

## Charles-only CA

This proxy **must** use the same CA certificate that the target app's `network_security_config.xml` trusts. The only supported path is the **Charles Proxy CA** — no auto-generation, no Frida, no alternative CAs.

## Requirements

- Node >= 18
- `adb` on PATH (for device proxy setup)
- Charles Proxy CA (cert + key exported from Charles)

## Setup

No clone needed. The server is installed from the npm registry (prebuilt `dist/` — no devDeps, no build step), then registered with your MCP client.

```bash
# verify the CLI works once
npx -y @shahfazliz/proxy-mcp@latest --help
```

> **Updates:** use `@latest` so new releases are picked up automatically — no cache clearing, no config changes. If you need reproducibility (e.g. comparing behavior across sessions), pin a specific version like `@0.1.1` instead.

### 1. Extract your Charles Proxy CA

Charles stores its CA at `~/Library/Application Support/Charles/ca/`. Extract the cert and key into your project's `.proxy-ca/` directory:

**Step 1: Export the Charles CA (one-time setup)**
- In Charles: **Help → SSL Proxying → Export Charles Certificate and Private Key**
- Save as `.p12` file (password-protected or empty password - your choice)

**Step 2: Extract to `.proxy-ca/`**
`.proxy-ca` can be anywhere on your computer. I like to put them in ~/.certificates/ where I put all other certs there
```bash
# If exported with password
npx proxy-mcp-cli ca:import --p12 ~/path/to/charles-ssl-proxying.p12 --password yourpassword

# If exported with empty password (default)
npx proxy-mcp-cli ca:import --p12 ~/path/to/charles-ssl-proxying.p12

# Or manually extract
mkdir -p .proxy-ca
openssl pkcs12 -in ~/path/to/charles-ssl-proxying.p12 \
  -nocerts -nodes -passin pass:yourpassword -out /path/to/.proxy-ca/key.pem
openssl pkcs12 -in ~/path/to/charles-ssl-proxying.p12 \
  -clcerts -nokeys -passin pass:yourpassword -out /path/to/.proxy-ca/cert.pem
```

Both files must be clean PEM (no Bag Attributes, no PKCS12 wrapping). The key must be an unencrypted RSA private key.

### 2. Register with Cursor / any MCP client

Use `@latest` to always get the newest release (see the note in Setup):

```json
{
  "mcpServers": {
    "shah-proxy": {
      "command": "npx",
      "args": [
        "-y",
        "@shahfazliz/proxy-mcp@latest",
        "--ca-dir",
        "/absolute/path/to/.proxy-ca"
      ],
      "enabled": true
    }
  }
}
```

Alternative for zero-npx: `npm install -g @shahfazliz/proxy-mcp`, then set `command` to `proxy-mcp` with the same args. Update with `npm update -g @shahfazliz/proxy-mcp`.

`--ca-dir` must point to a directory containing `cert.pem` and `key.pem` (see step 1). If you omit it entirely, the server auto-discovers the CA in order: `<cwd>/.proxy-ca`, `~/.proxy-ca`, then `~/Library/Application Support/Charles/ca` — and reports which source it used (see `proxy_health.caStatus` → `source`).

## Quick start

```bash
# 1. Start proxy (port 8889, Metro dev server passthrough)
proxy_start --passthroughHosts '["localhost:8081"]'

# On an Android emulator, also map its 10.0.2.2 alias to the host loopback
# so Metro/dev-server passthrough can reach the Mac:
proxy_start --port 8889 --passthroughHosts '["10.0.2.2:8081"]' \
  --hostRewrites '[{ "match": "10.0.2.2:8081", "upstream": "127.0.0.1:8081" }]'

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

## MCP tools (21)

| Tool | Purpose |
|------|---------|
| `proxy_start` / `proxy_stop` | Start/stop the MITM proxy |
| `proxy_health` | Full preflight: running state, version, capabilities, CA status (cert/key present + matching + fingerprint), detected LAN IP, port availability, suggested `proxy_start` args |
| `proxy_mock_response` | Static mock response for a URL pattern |
| `proxy_mock_transform` | JSON transform rule for a URL pattern |
| `proxy_update_transform` | Idempotent upsert of a transform rule |
| `proxy_list_mocks` / `proxy_clear_mocks` | Manage mock responses |
| `proxy_list_transforms` / `proxy_clear_transforms` | Manage transform rules |
| `proxy_request_transform` | Modify outgoing requests (headers/query/body) before forwarding |
| `proxy_list_request_transforms` / `proxy_clear_request_transforms` | Manage request-transform rules |
| `proxy_update_request_transform` | Idempotent upsert of a request-transform rule |
| `proxy_list_traffic` | Captured requests with transform outcomes + optional body previews |
| `proxy_probe_transform` | One-shot fetch + dry-run patch, returns before/after |
| `proxy_save_transforms` / `proxy_load_transforms` | Persist/restore response + request transforms to JSON file |
| `proxy_scope` | Set/clear capture scope: which hosts' traffic is retained in the log |
| `proxy_whats_new` | Running vs published version + changelog of recent releases |
| `ca_info` | CA fingerprint, trust model (app-bundled vs device install), setup instructions |

The server also ships an `instructions` block (delivered during MCP initialization) that tells agents the canonical workflow and gotchas, so they don't need this README to get a first run working.

Full parameter docs for each tool live in the `proxy_start` / `proxy_*` tool schemas (visible to MCP clients), plus the project wiki (a local Obsidian vault — not committed to this repo).

## App dependency

Your debug APK must trust the proxy's CA. For an Android TV app:

- Set `enableSystemProxy=true` in `apps/tv/android/gradle.properties`
- This bakes the CA cert into the APK via `res/raw/cacert`
- Verify the fingerprint from `ca_info` matches the app's bundled cert

No device-side CA installation, no root, no Magisk needed — trust is app-bundled.

## CLI fallback

```bash
npx proxy-mcp-cli start --port 8889 --passthrough 10.0.2.2:8081 --host-rewrite 10.0.2.2:8081=127.0.0.1:8081
npx proxy-mcp-cli status
npx proxy-mcp-cli ca-info
npx proxy-mcp-cli ca:import --p12 /path/to/charles-ssl-proxying.p12
npx proxy-mcp-cli transform add GET "https://..." patches.json
npx proxy-mcp-cli req-transform add GET viewBundle setHeaders='{"x-custom":"v"}' list
npx proxy-mcp-cli traffic --filter example
npx proxy-mcp-cli mock add GET "https://example.com/api/people" /tmp/fixture.json --delay 2000 --bandwidth 50
npx proxy-mcp-cli scope set api.example.com   # retain only interesting hosts
npx proxy-mcp-cli scope get
```

## Mock speed control

`proxy_mock_response` (and the CLI `mock add` command) accept two optional knobs to simulate a slow, far-away server — useful when you want to reproduce loading states, spinners, or timeouts on the device:

- `delayMs` — server processing time. The proxy waits this long before sending a single byte.
- `bandwidthKbps` — network bandwidth cap. The body is re-streamed at this rate (KB/s), so a large payload arrives progressively instead of all at once.

```json
{
  "method": "GET",
  "url": "api.example.com/v1/user",
  "bodyFile": "/tmp/user.json",
  "delayMs": 2000,
  "bandwidthKbps": 50
}
```

Both are optional and independent; combine them for a full "slow server" experience.

## Capture scoping

During bug investigation, `proxy_list_traffic` returns **every** captured host into the agent's context — noisy and token-heavy. `scope` restricts which traffic is **retained**:

- The proxy still MITMs and serves **all** hosts (discovery is unaffected) — scope only controls what appears in the log.
- Scope by **hostname**, not path: `api.example.com` keeps that host plus its subdomains (`sub.api.example.com`); `*.example.com` wildcards are also accepted.
- Narrow it **mid-session**: start wide, then scope once the interesting host shows up.
- Already-captured entries are unaffected when you change scope.

At start (via `proxy_start` or CLI):

```json
{ "scope": ["api.example.com"] }
```

```bash
npx proxy-mcp-cli start --port 8889 --scope api.example.com,cdn.example.com
```

At runtime (MCP tool or CLI):

```
proxy_scope --hosts '["api.example.com"]'   # set scope
proxy_scope                                 # clear scope (retain all)
```

```bash
npx proxy-mcp-cli scope set api.example.com,cdn.example.com
npx proxy-mcp-cli scope clear
npx proxy-mcp-cli scope get
```

Default `scope: []` (or unset) = capture all traffic, matching the pre-scoping behavior.

## Allowed directories

File-access tools (`bodyFile` on mocks, `proxy_save_transforms`, `proxy_load_transforms`, and CLI patch files) only read/write inside the folder the proxy was launched from. Add other directories at launch with a repeatable `--allowed-dir <path>` flag or the `SHAH_PROXY_ALLOWED_DIRS` env var (comma-separated). The list is fixed at startup — tools cannot widen it at runtime.

```bash
npx proxy-mcp-cli --allowed-dir /Users/me/shared-fixtures start
```

## Metro passthrough

The proxy automatically forwards Metro bundler requests (`:8081`) to the local dev server. Headers like `newrelic`, `traceparent`, `tracestate`, and `accept-encoding` are stripped from forwarded Metro requests to avoid breaking the bundler.

`localhost:8081`, `127.0.0.1:8081`, and the detected LAN IP at `:8081` are always auto-added to passthrough — pass `passthroughHosts` only for additional hosts.

## Android emulator host rewrites (`hostRewrites`)

Android emulators reach the host machine's loopback via the special alias `10.0.2.2`. That address only exists **inside the emulator's network namespace** — it is not a real, reachable address from the Mac. When the app calls Metro through the proxy with `Host: 10.0.2.2:8081`, the proxy must translate it to `127.0.0.1:8081` before dialing, or the fetch hangs / returns `502 Error communicating with upstream server`.

Pass `hostRewrites` to `proxy_start`:

```json
{
  "port": 8889,
  "passthroughHosts": ["10.0.2.2:8081"],
  "hostRewrites": [
    { "match": "10.0.2.2:8081", "upstream": "127.0.0.1:8081" }
  ]
}
```

- `match` — the host:port as it arrives in the request (hostname or `hostname:port`).
- `upstream` — the host:port the proxy should actually dial instead.
- Applies to both HTTP passthrough and WebSocket passthrough targets.
- Add `10.0.2.2` (and its port) to `passthroughHosts` as well, so the request is not MITM'd before the rewrite happens.
- `proxy_health` reports the active `hostRewrites` and `passthroughHosts`, so the agent can verify the mapping took effect.
- CLI equivalent: `--host-rewrite 10.0.2.2:8081=127.0.0.1:8081`.

## Releasing

Publish a new version to npm. Users on `@latest` get it automatically on next launch — no git installs, no cache clearing:

```bash
npm run release:patch   # or release:minor / release:major
```

This runs `npm version <level>` (bump + tag) then `npm publish` (builds, publishes, sets the `latest` tag). Prefer semver: `patch` for bug fixes, `minor` for new features, `major` for breaking changes.

## Git-ignored (keep local)

- `.proxy-ca/` — CA private key + cert
- `transforms.json` — auto-saved on proxy stop
- `traffic-*.json` / `*.har` — exported traffic logs
- `*.p12`, `cacert.pem` — raw Charles exports

## License

UNLICENSED — internal tool. Not distributed publicly.
