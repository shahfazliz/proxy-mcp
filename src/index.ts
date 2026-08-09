#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { proxy, ProxyManager, DEFAULT_PORT, type JsonPatch } from "./proxy.js";
import { getCaCertPath, getCaKeyPath, setCaDir, ensureCA, sha256Fingerprint } from "./ca.js";
import { getLanIp } from "./net.js";

const execFileAsync = promisify(execFile);

export const server = new McpServer({
  name: "shah-proxy-mcp",
  version: "0.1.0",
});

function text(value: unknown) {
  const body = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: "text" as const, text: body }] };
}

function fail(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  return { content: [{ type: "text" as const, text: `Error: ${message}` }], isError: true };
}

server.registerTool(
  "proxy_start",
  {
    title: "Start MITM proxy",
    description:
      "Bring up the mockttp HTTPS MITM proxy. Returns the LAN IP : port to type into the device's manual Wi-Fi proxy settings. Unmatched requests pass through to the real headend. " +
      "If the device is an Android emulator, pass hostRewrites to map its 10.0.2.2 alias (means 'host loopback', only valid inside the emulator) to 127.0.0.1 so Metro/dev-server passthrough can reach the Mac.",
    inputSchema: {
      port: z
        .number()
        .int()
        .optional()
        .describe(`TCP port to listen on (default ${DEFAULT_PORT}).`),
      passthroughHosts: z
        .array(z.string())
        .optional()
        .describe(
          "Host:port entries whose traffic should bypass MITM interception entirely (e.g. the React Native Metro bundler). " +
            "Each entry is 'hostname' or 'hostname:port'. The hostname is matched against CONNECT tunnels; port globs (e.g. ':808*') are " +
            "recorded for future HTTP-level filtering. Example: ['192.168.0.2:8081', 'localhost:8081'].",
        ),
      hostRewrites: z
        .array(z.object({
          match: z.string().describe("Host or host:port as it arrives in the request, e.g. '10.0.2.2:8081'."),
          upstream: z.string().describe("Host or host:port to dial instead, e.g. '127.0.0.1:8081'."),
        }))
        .optional()
        .describe(
          "Rewrite the upstream dial target for passthrough traffic. Use this when a device reaches the dev PC via a special alias that is not a real address on the Mac — e.g. the Android emulator's 10.0.2.2:8081 (maps to host loopback only from inside the emulator) -> 127.0.0.1:8081.",
        ),
      restoreTransforms: z
        .string()
        .optional()
        .describe(
          "Path to a JSON file previously saved by proxy_save_transforms. Transforms are restored idempotently (by method+url+regex).",
        ),
      scope: z
        .array(z.string())
        .optional()
        .describe(
          "Capture-scope hostnames: only traffic for these hosts (and their subdomains) is retained in the log, to keep agent context small. " +
            "Default [] (or omitted) = retain all captured traffic. Entries are hostnames or wildcard '*.example.com'. " +
            "The proxy still MITMs and serves ALL hosts — scope only controls what is retained in proxy_list_traffic. Adjust at runtime with proxy_scope.",
        ),
    },
  },
  async ({ port, passthroughHosts, hostRewrites, restoreTransforms, scope }) => {
    try {
      const info = await proxy.start({ port, passthroughHosts, hostRewrites, restoreTransforms, captureScope: scope });
      return text({
        status: "running",
        proxy: info.url,
        host: info.host,
        port: info.port,
        captureScope: proxy.getCaptureScope(),
        hint: `Set the device Wi-Fi proxy to ${info.url}, then install the CA (see ca_info).`,
      });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_stop",
  {
    title: "Stop MITM proxy",
    description:
      "Stop the proxy. Transform rules are auto-saved to transforms.json for next restart. Device proxy may still be set on the device — use proxy_health to detect this.",
    inputSchema: {},
  },
  async () => {
    try {
      const result = await proxy.stop();
      return text({ status: "stopped", ...result });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_mock_response",
  {
    title: "Add a mock rule",
    description:
      "Add an in-memory mock rule. Matches on HTTP method + URL pattern (glob/substring by default against the full URL; set regex=true for a raw regex). Body is supplied inline or via a fixture file on disk. Provide either 'body' or 'bodyFile', not both. " +
      "Optionally simulate a slow server: delayMs waits before responding (processing time), bandwidthKbps streams the body at a KB/s rate (slow network / big object from far away).",
    inputSchema: {
      method: z
        .string()
        .describe("HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, or OPTIONS."),
      url: z
        .string()
        .describe(
          "URL pattern. Default is glob/substring matched against the full absolute URL (e.g. 'api.example.com/v1/user' or '*/v1/user'). With regex=true, a raw JS regex source.",
        ),
      regex: z.boolean().optional().describe("Treat 'url' as a raw regex (default false)."),
      status: z.number().int().optional().describe("Response status code (default 200)."),
      headers: z
        .record(z.string())
        .optional()
        .describe("Response headers, e.g. { \"content-type\": \"application/json\" }."),
      body: z.string().optional().describe("Inline response body (small payloads)."),
      bodyFile: z
        .string()
        .optional()
        .describe("Path to a fixture file whose contents become the response body (large payloads). Must be inside the proxy's allowed directories (default: the folder the proxy was launched from). Add --allowed-dir <path> at launch to permit others."),
      delayMs: z
        .number()
        .int()
        .positive()
        .optional()
        .describe("Simulated server processing time: delay in milliseconds before the response starts (e.g. 3000 = 3s before the first byte)."),
      bandwidthKbps: z
        .number()
        .positive()
        .optional()
        .describe("Simulated network bandwidth cap: stream the body at this many KB/s (e.g. 50 = slow-network feel, big objects arrive progressively)."),
    },
  },
  async (args) => {
    try {
      const rule = await proxy.addMock(args);
      return text({ status: "added", rule });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_list_mocks",
  {
    title: "List active mock rules",
    description: "View the active in-memory mock rules.",
    inputSchema: {},
  },
  async () => {
    try {
      const mocks = proxy.listMocks();
      return text({ count: mocks.length, mocks });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_clear_mocks",
  {
    title: "Clear mock rules",
    description: "Remove one mock rule by id, or all rules if no id is given.",
    inputSchema: {
      id: z.string().optional().describe("Rule id to remove. Omit to clear all rules."),
    },
  },
  async ({ id }) => {
    try {
      const removed = await proxy.clearMocks(id);
      return text({ status: "cleared", removed });
    } catch (err) {
      return fail(err);
    }
  },
);

const jsonPatchSchema = z.object({
  path: z.string().describe(
    "Dotted path with `[]` for array wildcards, e.g. `schedules[].contents[].consumables[]`.",
  ),
  where: z.record(z.unknown()).optional().describe(
    "Optional condition: only modify items whose fields match all these values, e.g. `{ \"isMultiview\": true }`.",
  ),
  set: z.record(z.unknown()).describe(
    "Fields to set on matching items. Use `__NOW__` for current UTC time and `__NOW_PLUS_<N><UNIT>__` (UNIT: S/M/H) for relative times, e.g. `__NOW_PLUS_3M__`.",
  ),
});

server.registerTool(
  "proxy_mock_transform",
  {
    title: "Add an intercept-and-transform rule",
    description:
      "Intercept a request, forward it to the real backend, parse the JSON response, apply in-place patches (path + optional where + set), and return the modified response. " +
      "Use `[]` for array wildcards in path, `where` for conditional matching, and `__NOW__` / `__NOW_PLUS_<N><UNIT>__` macros for dynamic timestamps.",
    inputSchema: {
      method: z
        .string()
        .describe("HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, or OPTIONS."),
      url: z
        .string()
        .describe(
          "URL pattern. Default is glob/substring matched against the full absolute URL. With regex=true, a raw JS regex source.",
        ),
      regex: z.boolean().optional().describe("Treat 'url' as a raw regex (default false)."),
      patches: z.array(jsonPatchSchema).min(1).describe("One or more JSON patch operations."),
    },
  },
  async (args) => {
    try {
      const rule = await proxy.addTransform(args);
      return text({ status: "added", rule });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_list_transforms",
  {
    title: "List active transform rules",
    description: "View the active intercept-and-transform rules.",
    inputSchema: {},
  },
  async () => {
    try {
      const transforms = proxy.listTransforms();
      return text({ count: transforms.length, transforms });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_clear_transforms",
  {
    title: "Clear transform rules",
    description: "Remove one transform rule by id, or all transform rules if no id is given.",
    inputSchema: {
      id: z.string().optional().describe("Transform rule id to remove. Omit to clear all."),
    },
  },
  async ({ id }) => {
    try {
      const removed = await proxy.clearTransforms(id);
      return text({ status: "cleared", removed });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_request_transform",
  {
    title: "Add a request-modification rule",
    description:
      "Intercept a request matching method+URL, modify it (headers, query params, body), forward to the real backend, and return the response. " +
      "Use setHeaders/removeHeaders to modify headers, setQuery/removeQuery for URL params, and body to replace the request body.",
    inputSchema: {
      method: z.string().describe("HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, or OPTIONS."),
      url: z.string().describe("URL pattern (glob/substring by default, regex=true for raw regex)."),
      regex: z.boolean().optional().describe("Treat 'url' as a raw regex (default false)."),
      setHeaders: z.record(z.string()).optional().describe("Headers to add or override (e.g. { \"x-custom\": \"val\" })."),
      removeHeaders: z.array(z.string()).optional().describe("Headers to strip from the outgoing request (e.g. [\"x-newrelic\"])."),
      setQuery: z.record(z.string()).optional().describe("Query params to add or override (e.g. { \"include\": \"extended\" })."),
      removeQuery: z.array(z.string()).optional().describe("Query params to strip from the URL (e.g. [\"legacy\"])."),
      body: z.string().optional().describe("Replace the request body (for POST/PUT)."),
    },
  },
  async (args) => {
    try {
      const rule = await proxy.addRequestTransform(args);
      return text({ status: "added", rule });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_list_request_transforms",
  {
    title: "List active request-modification rules",
    description: "View the active request transform rules.",
    inputSchema: {},
  },
  async () => {
    try {
      const transforms = proxy.listRequestTransforms();
      return text({ count: transforms.length, transforms });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_clear_request_transforms",
  {
    title: "Clear request-modification rules",
    description: "Remove one request transform rule by id, or all rules if no id is given.",
    inputSchema: {
      id: z.string().optional().describe("Rule id to remove. Omit to clear all."),
    },
  },
  async ({ id }) => {
    try {
      const removed = await proxy.clearRequestTransforms(id);
      return text({ status: "cleared", removed });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_update_request_transform",
  {
    title: "Add or update a request-modification rule (idempotent upsert)",
    description:
      "Idempotently upsert a request transform rule by (method + url + regex) key. " +
      "If a rule with the same key exists, its properties are replaced.",
    inputSchema: {
      method: z.string().describe("HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, or OPTIONS."),
      url: z.string().describe("URL pattern (glob/substring by default, regex=true for raw regex)."),
      regex: z.boolean().optional().describe("Treat 'url' as a raw regex (default false)."),
      setHeaders: z.record(z.string()).optional().describe("Headers to add or override."),
      removeHeaders: z.array(z.string()).optional().describe("Headers to strip from the outgoing request."),
      setQuery: z.record(z.string()).optional().describe("Query params to add or override."),
      removeQuery: z.array(z.string()).optional().describe("Query params to strip from the URL."),
      body: z.string().optional().describe("Replace the request body."),
    },
  },
  async (args) => {
    try {
      const rule = await proxy.updateRequestTransform(args);
      return text({ status: "upserted", rule });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_list_traffic",
  {
    title: "List / export captured traffic",
    description:
      "Confirm a rule matched the intended request by inspecting captured traffic. Each entry includes transformOutcome (patched|no_match|not_json|error) and patchesApplied count. " +
      "Sensitive headers (authorization, cookies, api keys) are redacted by default — set includeSensitiveHeaders=true to see raw values. " +
      "Use includeRequestBodyPreviews=true to see POST/PUT body content. Use includeResponseBodyPreviews=true for response samples. " +
      "Optionally export to JSON or HAR (replaces the Charles log-export workflow).",
    inputSchema: {
      filter: z
        .string()
        .optional()
        .describe("Case-insensitive substring filter on method or URL."),
      export: z.enum(["json", "har"]).optional().describe("Write captured traffic to a file."),
      includeBodies: z.boolean().optional().describe("Include response body previews (default false). Deprecated: use includeResponseBodyPreviews."),
      includeRequestBodyPreviews: z.boolean().optional().describe("Include request body previews (default false)."),
      includeResponseBodyPreviews: z.boolean().optional().describe("Include response body previews (default false)."),
      includeSensitiveHeaders: z
        .boolean()
        .optional()
        .describe("Include raw sensitive headers (authorization, cookies, api keys) in the output. Default false — values are redacted as [REDACTED]."),
    },
  },
  async ({ filter, export: exportFormat, includeBodies, includeRequestBodyPreviews, includeResponseBodyPreviews, includeSensitiveHeaders }) => {
    try {
      const showBodies = includeRequestBodyPreviews || includeResponseBodyPreviews || includeBodies;
      const entries = proxy.listTraffic(filter, {
        includeBodies: showBodies,
        includeSensitiveHeaders,
      });
      if (exportFormat) {
        const path = await proxy.exportTraffic(exportFormat, filter, { includeSensitiveHeaders });
        return text({ count: entries.length, exported: path, hint: "Use includeBodies=true for body previews." });
      }
      // Inline: include body previews only if explicitly requested.
      const result = showBodies
        ? entries
        : entries.map((e) => {
            const { responseBodyPreview, ...rest } = e;
            return rest;
          });
      return text({ count: entries.length, traffic: result });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "ca_info",
  {
    title: "CA path + device install instructions",
    description:
      "Print the persistent CA path and per-device install instructions. Optionally push the cert to a USB-connected Android phone via adb.",
    inputSchema: {
      adbPush: z
        .boolean()
        .optional()
        .describe("If true, run `adb push` to copy the CA cert to a USB-connected Android device."),
    },
  },
  async ({ adbPush }) => {
    try {
      const { cert } = await ensureCA();
      const lanIp = getLanIp();
      const fingerprint = sha256Fingerprint(cert);

      const result: Record<string, unknown> = {
        caCert: getCaCertPath(),
        caKey: getCaKeyPath(),
        sha256Fingerprint: fingerprint,
        // The PEM wrapped with Bag Attributes (PKCS12) is NOT the file to bundle.
        // Always use .proxy-ca/cert.pem (clean PEM, cert-only) for the app's cacert.pem.
        certFormat: "clean PEM (cert-only, no PKCS12 Bag Attributes)",
        warning:
          "The app's bundled cacert.pem MUST match this exact file (.proxy-ca/cert.pem). " +
          "Do NOT use ~/.certificates/cacert.pem (PKCS12-wrapped format). " +
          `Verify: after rebuilding the debug APK, check the SHA-256 fingerprint matches ${fingerprint}.`,
        instructions: {
          general: `Set the device Wi-Fi proxy to ${lanIp}:${DEFAULT_PORT}, then install the CA cert once (like the Charles CA).`,
          fireTV: "Settings > Network: set manual proxy to the PC IP:port. Install the CA cert (sideload/file manager).",
          chromecast: "Set manual proxy to the PC IP:port. May work without a CA for some endpoints; install the CA if HTTPS endpoints fail.",
          androidPhone: "Wi-Fi > modify network > manual proxy to PC IP:port. Install CA via Settings > Security > Install from storage. Or use adbPush=true over USB.",
          androidTvEmulator: [
            "The emulator cannot install user CAs via Settings UI or intent.",
            "Preferred path: rebuild the debug APK with enableSystemProxy=true, bundling .proxy-ca/cert.pem as cacert.pem.",
            `Proxy address from emulator: 10.0.2.2:${DEFAULT_PORT} (maps to host loopback).`,
            "Set proxy: adb shell settings put global http_proxy 10.0.2.2:8889",
            "Clear proxy: adb shell settings put global http_proxy :0",
          ].join("\n"),
        },
      };

      if (adbPush) {
        try {
          const { stdout } = await execFileAsync("adb", [
            "push",
            getCaCertPath(),
            "/sdcard/Download/shah-proxy-ca.pem",
          ]);
          result.adbPush = {
            status: "pushed",
            dest: "/sdcard/Download/shah-proxy-ca.pem",
            note: "Install it via Settings > Security > Install a certificate > CA certificate.",
            output: stdout.trim(),
          };
        } catch (adbErr) {
          result.adbPush = {
            status: "failed",
            error: adbErr instanceof Error ? adbErr.message : String(adbErr),
          };
        }
      }

      return text(result);
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_health",
  {
    title: "Check proxy health and diagnostics",
    description:
      "Returns whether the proxy is running, port, rule counts, captured traffic, last request timestamp, last error, and warnings (e.g. if proxy is stopped but device proxy may still be set). Use this first when proxy_list_traffic returns empty.",
    inputSchema: {},
  },
  async () => {
    try {
      return text(proxy.getHealth());
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_scope",
  {
    title: "Set or clear the capture scope (retention scoping)",
    description:
      "Restrict which traffic is retained in the proxy log (proxy_list_traffic). The proxy still intercepts and serves all hosts — this only controls what is kept, so the agent's context stays small during bug investigation. " +
      "Pass 'hosts' to retain only matching hostnames (their subdomains are included, and '*.example.com' wildcards are allowed); omit 'hosts' or pass [] to clear scoping and retain all traffic again. " +
      "Returns the active scope and current captured-traffic count. Already-captured entries are unaffected.",
    inputSchema: {
      hosts: z
        .array(z.string())
        .optional()
        .describe("Hostnames to retain, e.g. ['api.cld.example.com']. Omit or [] = retain all traffic (no scoping)."),
    },
  },
  async ({ hosts }) => {
    try {
      const result = proxy.setCaptureScope(hosts ?? []);
      return text(result);
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_update_transform",
  {
    title: "Add or update an intercept-and-transform rule (idempotent upsert)",
    description:
      "Idempotently upsert a transform rule by (method + url + regex) key. If a rule with the same key exists, its patches are replaced. Use this instead of clear+re-add to avoid auto-review friction.",
    inputSchema: {
      method: z
        .string()
        .describe("HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, or OPTIONS."),
      url: z
        .string()
        .describe(
          "URL pattern. Default is glob/substring matched against the full absolute URL. Use a short substring like 'viewMultiviews' to avoid classifier issues with full URLs.",
        ),
      regex: z.boolean().optional().describe("Treat 'url' as a raw regex (default false)."),
      patches: z.array(jsonPatchSchema).min(1).describe("One or more JSON patch operations."),
    },
  },
  async (args) => {
    try {
      const rule = await proxy.updateTransform(args);
      return text({ status: "upserted", rule });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_save_transforms",
  {
    title: "Persist all transform rules to a JSON file",
    description:
      "Save both response and request transform rules to a JSON file for reuse after a proxy restart. Reload with proxy_load_transforms.",
    inputSchema: {
      path: z
        .string()
        .optional()
        .describe("File path to save to (default: transforms.json in project root). Must be inside the proxy's allowed directories (default: the folder the proxy was launched from); extend with --allowed-dir <path>."),
    },
  },
  async ({ path }) => {
    try {
      const savePath = await proxy.saveTransformsToFile(path ?? "transforms.json");
      return text({ status: "saved", path: savePath });
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_probe_transform",
  {
    title: "One-shot: test transform rules without registering them",
    description:
      "Fetch a URL directly, apply the given patches, and return a sample of modified fields (before/after values) plus match count. " +
      "Useful for verifying patch paths and wire values before calling proxy_update_transform. Does NOT require the proxy to be running.",
    inputSchema: {
      url: z.string().describe("Full URL to fetch and patch (e.g. https://api.cld.dtvce.com/...)."),
      patches: z.array(jsonPatchSchema).min(1).describe("JSON patch operations to test."),
    },
  },
  async ({ url, patches }: { url: string; patches: JsonPatch[] }) => {
    try {
      const result = await ProxyManager.probeTransform(url, patches);
      return text(result);
    } catch (err) {
      return fail(err);
    }
  },
);

server.registerTool(
  "proxy_load_transforms",
  {
    title: "Load transform rules from a JSON file",
    description:
      "Load transform rules previously saved with proxy_save_transforms. Uses idempotent upsert (requires proxy to be running).",
    inputSchema: {
      path: z
        .string()
        .optional()
        .describe("File path to load from (default: transforms.json in project root). Must be inside the proxy's allowed directories (default: the folder the proxy was launched from); extend with --allowed-dir <path>."),
    },
  },
  async ({ path }) => {
    try {
      const result = await proxy.loadTransformsFromFile(path ?? "transforms.json");
      const total = result.responseTransforms.length + result.requestTransforms.length;
      return text({ status: "loaded", total, responseTransforms: result.responseTransforms.length, requestTransforms: result.requestTransforms.length, response: result.responseTransforms, request: result.requestTransforms });
    } catch (err) {
      return fail(err);
    }
  },
);

export async function main(): Promise<void> {
  const caDirIdx = process.argv.indexOf("--ca-dir");
  if (caDirIdx !== -1 && process.argv[caDirIdx + 1]) {
    setCaDir(process.argv[caDirIdx + 1]);
  }
  const allowedDirs: string[] = [];
  let i = process.argv.length;
  while (i-- > 0) {
    if (process.argv[i] === "--allowed-dir" && process.argv[i + 1]) {
      allowedDirs.push(process.argv[i + 1]);
    }
  }
  allowedDirs.push(
    ...(process.env.SHAH_PROXY_ALLOWED_DIRS ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
  proxy.setAllowedDirs(allowedDirs);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("shah-proxy-mcp running on stdio");
}

// Only auto-start the stdio transport when run directly (keeps the module
// importable for tests / preflight checks). Uses realpath to handle symlinks
// (e.g. when npx installs from git and runs the bin through a symlink).
if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  main().catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
  });
}
