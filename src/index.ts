#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
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
      "Bring up the mockttp HTTPS MITM proxy. Returns the LAN IP : port to type into the device's manual Wi-Fi proxy settings. Unmatched requests pass through to the real headend.",
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
      restoreTransforms: z
        .string()
        .optional()
        .describe(
          "Path to a JSON file previously saved by proxy_save_transforms. Transforms are restored idempotently (by method+url+regex).",
        ),
    },
  },
  async ({ port, passthroughHosts, restoreTransforms }) => {
    try {
      const info = await proxy.start({ port, passthroughHosts, restoreTransforms });
      return text({
        status: "running",
        proxy: info.url,
        host: info.host,
        port: info.port,
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
      "Add an in-memory mock rule. Matches on HTTP method + URL pattern (glob/substring by default against the full URL; set regex=true for a raw regex). Body is supplied inline or via a fixture file on disk. Provide either 'body' or 'bodyFile', not both.",
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
        .describe("Path to a fixture file whose contents become the response body (large payloads)."),
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
  "proxy_list_traffic",
  {
    title: "List / export captured traffic",
    description:
      "Confirm a rule matched the intended request by inspecting captured traffic. Each entry includes transformOutcome (patched|no_match|not_json|error) and patchesApplied count. " +
      "Optionally export to JSON or HAR (replaces the Charles log-export workflow).",
    inputSchema: {
      filter: z
        .string()
        .optional()
        .describe("Case-insensitive substring filter on method or URL."),
      export: z.enum(["json", "har"]).optional().describe("Write captured traffic to a file."),
      includeBodies: z.boolean().optional().describe("Include response body previews in the export (default false)."),
    },
  },
  async ({ filter, export: exportFormat, includeBodies }) => {
    try {
      const entries = proxy.listTraffic(filter);
      if (exportFormat) {
        const path = await proxy.exportTraffic(exportFormat, filter);
        return text({ count: entries.length, exported: path, hint: "Use includeBodies=true for body previews." });
      }
      // Inline: include body previews only if explicitly requested (responseBodyPreview is already on the entry).
      const result = includeBodies
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
    title: "Persist transform rules to a JSON file",
    description:
      "Save all current transform rules to a JSON file for reuse after a proxy restart. Rules are serialized without ids; reload with proxy_load_transforms.",
    inputSchema: {
      path: z
        .string()
        .optional()
        .describe("File path to save to (default: transforms.json in project root)."),
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
        .describe("File path to load from (default: transforms.json in project root)."),
    },
  },
  async ({ path }) => {
    try {
      const rules = await proxy.loadTransformsFromFile(path ?? "transforms.json");
      return text({ status: "loaded", count: rules.length, rules });
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
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("shah-proxy-mcp running on stdio");
}

// Only auto-start the stdio transport when run directly (keeps the module
// importable for tests / preflight checks).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
  });
}
