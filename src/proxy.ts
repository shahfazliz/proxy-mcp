import { getLocal, type Mockttp, type RequestRuleBuilder, type CompletedRequest } from "mockttp";
import { readFile, writeFile, access } from "node:fs/promises";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { ensureCA } from "./ca.js";
import { getLanIp, isPortFree, whoIsOnPort } from "./net.js";

export const DEFAULT_PORT = 8889;
const TRAFFIC_CAP = 1000;

const SUPPORTED_METHODS = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
] as const;
type Method = (typeof SUPPORTED_METHODS)[number];

export interface MockRuleInput {
  method: string;
  url: string;
  regex?: boolean;
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  bodyFile?: string;
}

export interface MockRule {
  id: string;
  method: Method;
  url: string;
  regex: boolean;
  status: number;
  headers?: Record<string, string>;
  bodySource: "inline" | "file" | "none";
  bodyFile?: string;
  bodyBytes: number;
  createdAt: string;
}

/** A JSON patch entry for the intercept-and-transform rule. */
export interface JsonPatch {
  /** Dotted path with `[]` for array wildcards, e.g. `schedules[].contents[].consumables[]`. */
  path: string;
  /** Optional condition: only modify items whose fields match all these values. */
  where?: Record<string, unknown>;
  /** Fields to set on matching items (supports `__NOW__`, `__NOW_PLUS_<N><UNIT>__` macros). */
  set: Record<string, unknown>;
}

export interface TransformRuleInput {
  method: string;
  url: string;
  regex?: boolean;
  patches: JsonPatch[];
}

export interface TransformRule {
  id: string;
  method: Method;
  url: string;
  regex: boolean;
  patches: JsonPatch[];
  createdAt: string;
}

interface TrafficEntry {
  id: string;
  method: string;
  url: string;
  matchedRuleId?: string;
  requestHeaders: Record<string, unknown>;
  requestAt: string;
  statusCode?: number;
  statusMessage?: string;
  responseHeaders?: Record<string, unknown>;
  responseAt?: string;
  /** Transform outcome: "patched" | "no_match" | "not_json" | "error" */
  transformOutcome?: string;
  /** Number of JSON nodes that matched `where` condition and were patched. */
  patchesApplied?: number;
  /** Truncated response body (first 500 chars) sampled after transform. */
  responseBodyPreview?: string;
}

/** Convert a user URL pattern into a RegExp used by mockttp's path/url matcher. */
function patternToRegex(pattern: string, isRegex: boolean): RegExp {
  if (isRegex) return new RegExp(pattern);
  // Glob/substring: escape regex specials, then treat `*` as a wildcard.
  // Unanchored => substring match against the full absolute URL.
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const globbed = escaped.replace(/\\\*/g, ".*");
  return new RegExp(globbed);
}

/** Parse a passthrough host string into hostname + optional port glob. */
function parsePassthroughHost(
  input: string,
): { hostname: string; portGlob?: string } {
  const colonIdx = input.lastIndexOf(":");
  if (colonIdx === -1) {
    return { hostname: input };
  }
  if (input.includes("]")) {
    const closeBracket = input.lastIndexOf("]");
    if (colonIdx > closeBracket) {
      return {
        hostname: input.slice(0, colonIdx),
        portGlob: input.slice(colonIdx + 1) || undefined,
      };
    }
    return { hostname: input };
  }
  return {
    hostname: input.slice(0, colonIdx),
    portGlob: input.slice(colonIdx + 1) || undefined,
  };
}

const PASSTHROUGH_SKIP_HEADERS = new Set([
  "host",
  "connection",
  "proxy-connection",
  "transfer-encoding",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
]);

/** Do not forward app telemetry or compression headers to Metro. */
const METRO_FORWARD_SKIP_HEADERS = new Set([
  ...PASSTHROUGH_SKIP_HEADERS,
  "newrelic",
  "traceparent",
  "tracestate",
  "x-newrelic-id",
  "accept-encoding",
]);

/** True when a plain HTTP/WS URL should bypass MITM and forward to Metro (or similar). */
function urlMatchesPassthroughHost(url: string, entry: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "ws:") {
    return false;
  }

  const { hostname, portGlob } = parsePassthroughHost(entry);
  const hostOk =
    parsed.hostname === hostname ||
    (hostname === "localhost" && parsed.hostname === "127.0.0.1") ||
    (hostname === "127.0.0.1" && parsed.hostname === "localhost");
  if (!hostOk) {
    return false;
  }

  const reqPort = parsed.port || "80";
  if (!portGlob) {
    return true;
  }
  if (portGlob.endsWith("*")) {
    return reqPort.startsWith(portGlob.slice(0, -1));
  }
  return reqPort === portGlob;
}

/** On the proxy host, `localhost` for Metro should hit loopback IPv4. */
function rewritePassthroughTargetUrl(url: string): string {
  const parsed = new URL(url);
  if (parsed.hostname === "localhost") {
    parsed.hostname = "127.0.0.1";
  }
  return parsed.toString();
}

function defaultPassthroughHosts(lanIp: string): string[] {
  return [`localhost:8081`, `127.0.0.1:8081`, `${lanIp}:8081`];
}

function mergePassthroughHosts(lanIp: string, userHosts?: string[]): string[] {
  const merged = new Set(defaultPassthroughHosts(lanIp));
  for (const entry of userHosts ?? []) {
    const trimmed = entry.trim();
    if (trimmed.length > 0) {
      merged.add(trimmed);
    }
  }
  return [...merged];
}

function buildPassthroughUrlPatterns(entries: string[]): RegExp[] {
  const patterns = new Set<string>();
  for (const entry of entries) {
    const { hostname, portGlob } = parsePassthroughHost(entry);
    const port = portGlob ?? "8081";
    const escapedHost = hostname.replace(/\./g, "\\.");
    patterns.add(`^https?://${escapedHost}:${port}`);
    patterns.add(`^wss?://${escapedHost}:${port}`);
    if (hostname === "localhost") {
      patterns.add(`^https?://127\\.0\\.0\\.1:${port}`);
      patterns.add(`^wss?://127\\.0\\.0\\.1:${port}`);
    }
  }
  return [...patterns].map((source) => new RegExp(source, "i"));
}

function resolvePassthroughRequestUrl(
  url: string,
  headers: Record<string, string | string[]>,
): string {
  if (
    url.startsWith("http://") ||
    url.startsWith("https://") ||
    url.startsWith("ws://") ||
    url.startsWith("wss://")
  ) {
    return rewritePassthroughTargetUrl(url);
  }
  const host = headers.host;
  if (typeof host === "string" && host.length > 0) {
    const path = url.startsWith("/") ? url : `/${url}`;
    return rewritePassthroughTargetUrl(`http://${host}${path}`);
  }
  return rewritePassthroughTargetUrl(url);
}

/** Parse a JSON path like `schedules[].contents[].consumables[]` into segments. */
function parseJsonPath(path: string): { key: string; isArray: boolean }[] {
  return path.split(".").map((seg) => ({
    key: seg.endsWith("[]") ? seg.slice(0, -2) : seg,
    isArray: seg.endsWith("[]"),
  }));
}

/** Walk the JSON tree and modify items at leaf segments matching `where`. */
function walkAndModify(
  obj: unknown,
  segments: { key: string; isArray: boolean }[],
  depth: number,
  where: Record<string, unknown>,
  set: Record<string, unknown>,
): number {
  if (obj == null || typeof obj !== "object") return 0;

  const seg = segments[depth];
  if (!seg) return 0;

  const target = (obj as Record<string, unknown>)[seg.key];
  if (target == null) return 0;

  const isLeaf = depth === segments.length - 1;
  let matchCount = 0;

  if (seg.isArray) {
    if (!Array.isArray(target)) return 0;
    for (const item of target) {
      if (isLeaf) {
        if (matchesWhere(item, where)) {
          applySetToItem(item, set);
          matchCount++;
        }
      } else {
        matchCount += walkAndModify(item, segments, depth + 1, where, set);
      }
    }
  } else {
    if (isLeaf) {
      if (matchesWhere(target, where)) {
        applySetToItem(target, set);
        matchCount++;
      }
    } else {
      matchCount += walkAndModify(target, segments, depth + 1, where, set);
    }
  }
  return matchCount;
}

/** Check if an item matches all key-value pairs in `where`. */
function matchesWhere(item: unknown, where: Record<string, unknown>): boolean {
  if (item == null || typeof item !== "object") return false;
  for (const [key, val] of Object.entries(where)) {
    if ((item as Record<string, unknown>)[key] !== val) return false;
  }
  return true;
}

/** Apply `set` fields to an object, resolving macros in string values. */
function applySetToItem(item: unknown, set: Record<string, unknown>): void {
  if (item == null || typeof item !== "object") return;
  for (const [key, val] of Object.entries(set)) {
    (item as Record<string, unknown>)[key] = val === "__NOW__"
      ? new Date().toISOString()
      : typeof val === "string" && val.startsWith("__NOW_PLUS_")
        ? resolveNowPlus(val)
        : val;
  }
}

/** Resolve `__NOW_PLUS_<N><UNIT>__` macros (e.g. `__NOW_PLUS_3M__` = +3 minutes). */
function resolveNowPlus(macro: string): string {
  const match = macro.match(/^__NOW_PLUS_(\d+)([SMH])__$/);
  if (!match) return macro;
  const amount = parseInt(match[1], 10);
  const unit = match[2];
  const ms = unit === "S" ? amount * 1000
    : unit === "M" ? amount * 60000
    : amount * 3600000;
  return new Date(Date.now() + ms).toISOString();
}

/** Resolve macros in a `set` record at rule-creation time (static values pass through). */
function resolveMacros(set: Record<string, unknown>): Record<string, unknown> {
  const resolved: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(set)) {
    if (val === "__NOW__" || (typeof val === "string" && val.startsWith("__NOW_PLUS_"))) {
      // Keep macro strings as-is; they are resolved at request time in applySetToItem.
      resolved[key] = val;
    } else {
      resolved[key] = val;
    }
  }
  return resolved;
}

export interface StartOptions {
  port?: number;
  passthroughHosts?: string[];
  restoreTransforms?: string;
}

export class ProxyManager {
  private server: Mockttp | undefined;
  private actualPort: number | undefined;
  private passthroughHosts: string[] = [];
  /** Live rule store; the resolved body is held alongside for re-applying. */
  private rules = new Map<string, { rule: MockRule; body?: string }>();
  /** Transform rules that intercept, forward, and modify JSON responses. */
  private transforms = new Map<string, TransformRule>();
  /** mockttp endpoint id -> our rule id (for translating matchedRuleId). */
  private endpointToRule = new Map<string, string>();
  private traffic = new Map<string, TrafficEntry>();
  private trafficOrder: string[] = [];
  /** Last request timestamp (for health diagnostics). */
  private lastRequestAt: string | undefined;
  /** Last error message from a transform or request failure. */
  private lastError: string | undefined;
  /** Transform outcomes keyed by request ID, surfaced in traffic entries. */
  private transformOutcomes = new Map<string, { outcome: string; count: number }>();
  /** Response body previews keyed by request ID (only for transform hits). */
  private bodyPreviews = new Map<string, string>();

  isRunning(): boolean {
    return this.server !== undefined;
  }

  get port(): number | undefined {
    return this.actualPort;
  }

  getHealth(): {
    running: boolean;
    port?: number;
    mockRules: number;
    transformRules: number;
    trafficCaptured: number;
    lastRequestAt?: string;
    lastError?: string;
    warnings?: string[];
  } {
    const warnings: string[] = [];
    if (!this.isRunning()) {
      warnings.push(
        "Proxy not running. If the device still has a proxy configured, traffic will fail. " +
        "Clear device proxy with: adb shell settings put global http_proxy :0",
      );
    }
    return {
      running: this.isRunning(),
      port: this.actualPort,
      mockRules: this.rules.size,
      transformRules: this.transforms.size,
      trafficCaptured: this.traffic.size,
      lastRequestAt: this.lastRequestAt,
      lastError: this.lastError,
      ...(warnings.length > 0 ? { warnings } : {}),
    };
  }

  async start(opts: StartOptions = {}): Promise<{ host: string; port: number; url: string }> {
    const port = opts.port ?? DEFAULT_PORT;
    if (this.server) {
      throw new Error(
        `Proxy already running on port ${this.actualPort}. Stop it first.`,
      );
    }
    if (!(await isPortFree(port))) {
      const occupant = await whoIsOnPort(port);
      throw new Error(
        occupant
          ? `Port ${port} is already in use by PID ${occupant.pid} (${occupant.command}). Kill it first (kill -9 ${occupant.pid}) or pass a different --port.`
          : `Port ${port} is already in use. Pass a different 'port'.`,
      );
    }

    const host = getLanIp();
    this.passthroughHosts = mergePassthroughHosts(host, opts.passthroughHosts);

    const { key, cert } = await ensureCA();

    const tlsPassthrough = this.buildTlsPassthrough();
    const server = getLocal({
      https: { key, cert, ...(tlsPassthrough.length > 0 ? { tlsPassthrough } : {}) },
      recordTraffic: true,
    });
    this.lastError = undefined;

    await server.start(port);
    this.server = server;
    this.actualPort = server.port;

    await this.applyRules();

    // Auto-restore from default transforms.json if not explicitly opted out via empty string.
    if (!opts.restoreTransforms || opts.restoreTransforms.length > 0) {
      const defaultPath = opts.restoreTransforms || resolve("transforms.json");
      try {
        await access(defaultPath);
        const data: TransformRuleInput[] = JSON.parse(await readFile(defaultPath, "utf8"));
        for (const input of data) {
          const method = input.method.toUpperCase() as Method;
          const existing = [...this.transforms.values()].find(
            (r) => r.method === method && r.url === input.url && r.regex === (input.regex ?? false),
          );
          if (existing) {
            existing.patches = input.patches;
          } else {
            this.transforms.set(randomUUID(), {
              id: randomUUID(),
              method,
              url: input.url,
              regex: input.regex ?? false,
              patches: input.patches,
              createdAt: new Date().toISOString(),
            });
          }
        }
        await this.applyRules();
      } catch {
        // File missing or invalid — ignore.
      }
    }

    // Backward compat: explicit path overrides defaults (still checked above).
    if (opts.restoreTransforms && opts.restoreTransforms.length > 0 && opts.restoreTransforms !== resolve("transforms.json")) {
      try {
        const loadedPath = resolve(opts.restoreTransforms);
        const data: TransformRuleInput[] = JSON.parse(await readFile(loadedPath, "utf8"));
        for (const input of data) {
          const method = input.method.toUpperCase() as Method;
          const existing = [...this.transforms.values()].find(
            (r) => r.method === method && r.url === input.url && r.regex === (input.regex ?? false),
          );
          if (existing) {
            existing.patches = input.patches;
          } else {
            this.transforms.set(randomUUID(), {
              id: randomUUID(),
              method,
              url: input.url,
              regex: input.regex ?? false,
              patches: input.patches,
              createdAt: new Date().toISOString(),
            });
          }
        }
        await this.applyRules();
      } catch {
        // Silent: restore file missing or invalid is not fatal.
      }
    }

    return { host, port: server.port, url: `${host}:${server.port}` };
  }

  /** Build the tlsPassthrough array from stored passthrough hosts. */
  private buildTlsPassthrough(): Array<{ hostname: string }> {
    const seen = new Set<string>();
    const result: Array<{ hostname: string }> = [];
    for (const entry of this.passthroughHosts) {
      const { hostname } = parsePassthroughHost(entry);
      if (!seen.has(hostname)) {
        seen.add(hostname);
        result.push({ hostname });
      }
    }
    return result;
  }

  async stop(): Promise<{ savedTransformsPath?: string; warnings: string[] }> {
    if (!this.server) throw new Error("Proxy is not running.");
    await this.server.stop();
    this.server = undefined;
    this.actualPort = undefined;
    const warnings: string[] = [];

    // Save transforms before clearing so they can be restored on next start.
    let savedTransformsPath: string | undefined;
    if (this.transforms.size > 0) {
      try {
        savedTransformsPath = resolve("transforms.json");
        const data = [...this.transforms.values()].map((r) => ({
          method: r.method,
          url: r.url,
          regex: r.regex,
          patches: r.patches,
        }));
        await writeFile(savedTransformsPath, JSON.stringify(data, null, 2));
      } catch {
        // Non-fatal.
      }
    }

    this.rules.clear();
    this.transforms.clear();
    this.endpointToRule.clear();
    this.traffic.clear();
    this.trafficOrder = [];

    warnings.push(
      "Device proxy may still point to this machine. " +
      "On the emulator: adb shell settings put global http_proxy :0",
    );

    return { savedTransformsPath, warnings };
  }

  async addMock(input: MockRuleInput): Promise<MockRule> {
    if (!this.server) {
      throw new Error("Proxy is not running. Call proxy_start first.");
    }

    const method = input.method.toUpperCase() as Method;
    if (!SUPPORTED_METHODS.includes(method)) {
      throw new Error(
        `Unsupported method '${input.method}'. Supported: ${SUPPORTED_METHODS.join(", ")}.`,
      );
    }
    if (input.body !== undefined && input.bodyFile !== undefined) {
      throw new Error("Provide either 'body' or 'bodyFile', not both.");
    }

    let body: string | undefined;
    let bodySource: MockRule["bodySource"] = "none";
    if (input.bodyFile !== undefined) {
      const path = resolve(input.bodyFile);
      body = await readFile(path, "utf8");
      bodySource = "file";
    } else if (input.body !== undefined) {
      body = input.body;
      bodySource = "inline";
    }

    const rule: MockRule = {
      id: randomUUID(),
      method,
      url: input.url,
      regex: input.regex ?? false,
      status: input.status ?? 200,
      headers: input.headers,
      bodySource,
      bodyFile: input.bodyFile,
      bodyBytes: body ? Buffer.byteLength(body) : 0,
      createdAt: new Date().toISOString(),
    };

    this.rules.set(rule.id, { rule, body });
    await this.applyRules();
    return rule;
  }

  listMocks(): MockRule[] {
    return [...this.rules.values()].map((r) => r.rule);
  }

  async clearMocks(id?: string): Promise<number> {
    if (!this.server) throw new Error("Proxy is not running.");
    let removed: number;
    if (id) {
      removed = this.rules.delete(id) ? 1 : 0;
      if (removed === 0) throw new Error(`No mock rule with id '${id}'.`);
    } else {
      removed = this.rules.size;
      this.rules.clear();
    }
    await this.applyRules();
    return removed;
  }

  /** Warn if a `set` value looks like a TypeScript enum key (underscores) but might be a wire value. */
  private static warnEnumPattern(val: unknown): void {
    if (typeof val === "string" && val.includes("_")) {
      console.error(
        `[shah-proxy] Warning: set value "${val}" contains underscores — this looks like a TypeScript enum key. ` +
        `Wire values may differ (e.g. "LINEAR_EVENT" vs "LINEAREVENT"). Verify against the actual headend response.`,
      );
    }
  }

  async addTransform(input: TransformRuleInput): Promise<TransformRule> {
    if (!this.server) {
      throw new Error("Proxy is not running. Call proxy_start first.");
    }

    const method = input.method.toUpperCase() as Method;
    if (!SUPPORTED_METHODS.includes(method)) {
      throw new Error(
        `Unsupported method '${input.method}'. Supported: ${SUPPORTED_METHODS.join(", ")}.`,
      );
    }
    if (!input.patches || input.patches.length === 0) {
      throw new Error("At least one patch is required.");
    }

    for (const p of input.patches) {
      for (const v of Object.values(p.set)) {
        ProxyManager.warnEnumPattern(v);
      }
    }

    const rule: TransformRule = {
      id: randomUUID(),
      method,
      url: input.url,
      regex: input.regex ?? false,
      patches: input.patches,
      createdAt: new Date().toISOString(),
    };

    this.transforms.set(rule.id, rule);
    await this.applyRules();
    return rule;
  }

  listTransforms(): TransformRule[] {
    return [...this.transforms.values()];
  }

  async clearTransforms(id?: string): Promise<number> {
    if (!this.server) throw new Error("Proxy is not running.");
    let removed: number;
    if (id) {
      removed = this.transforms.delete(id) ? 1 : 0;
      if (removed === 0) throw new Error(`No transform rule with id '${id}'.`);
    } else {
      removed = this.transforms.size;
      this.transforms.clear();
    }
    await this.applyRules();
    return removed;
  }

  /** Upsert a transform rule by (method, url, regex) key. Returns the new/updated rule. */
  async updateTransform(input: TransformRuleInput): Promise<TransformRule> {
    if (!this.server) {
      throw new Error("Proxy is not running. Call proxy_start first.");
    }

    const method = input.method.toUpperCase() as Method;
    if (!SUPPORTED_METHODS.includes(method)) {
      throw new Error(
        `Unsupported method '${input.method}'. Supported: ${SUPPORTED_METHODS.join(", ")}.`,
      );
    }
    if (!input.patches || input.patches.length === 0) {
      throw new Error("At least one patch is required.");
    }

    // Find existing rule by composite key (method + url + regex)
    const existing = [...this.transforms.values()].find(
      (r) => r.method === method && r.url === input.url && r.regex === (input.regex ?? false),
    );

    if (existing) {
      existing.patches = input.patches;
      await this.applyRules();
      return existing;
    }

    return this.addTransform(input);
  }

  /** Serialize all transform rules to a JSON file. */
  async saveTransformsToFile(filePath: string): Promise<string> {
    const path = resolve(filePath);
    const data = [...this.transforms.values()].map((r) => ({
      method: r.method,
      url: r.url,
      regex: r.regex,
      patches: r.patches,
    }));
    await writeFile(path, JSON.stringify(data, null, 2));
    return path;
  }

  /** Load transform rules from a JSON file and apply them. */
  async loadTransformsFromFile(filePath: string): Promise<TransformRule[]> {
    const path = resolve(filePath);
    const data: TransformRuleInput[] = JSON.parse(await readFile(path, "utf8"));
    const results: TransformRule[] = [];
    for (const input of data) {
      const rule = await this.updateTransform(input);
      results.push(rule);
    }
    return results;
  }

  listTraffic(filter?: string): TrafficEntry[] {
    const entries = this.trafficOrder
      .map((id) => this.traffic.get(id))
      .filter((e): e is TrafficEntry => e !== undefined);
    if (!filter) return entries;
    const needle = filter.toLowerCase();
    return entries.filter(
      (e) =>
        e.url.toLowerCase().includes(needle) ||
        e.method.toLowerCase().includes(needle),
    );
  }

  async exportTraffic(format: "json" | "har", filter?: string): Promise<string> {
    const entries = this.listTraffic(filter);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    if (format === "json") {
      const path = resolve(`traffic-${stamp}.json`);
      await writeFile(path, JSON.stringify(entries, null, 2));
      return path;
    }
    const path = resolve(`traffic-${stamp}.har`);
    await writeFile(path, JSON.stringify(this.toHar(entries), null, 2));
    return path;
  }

  private toHar(entries: TrafficEntry[]): object {
    return {
      log: {
        version: "1.2",
        creator: { name: "shah-proxy-mcp", version: "0.1.0" },
        entries: entries.map((e) => ({
          startedDateTime: e.requestAt,
          time: 0,
          request: {
            method: e.method,
            url: e.url,
            httpVersion: "HTTP/1.1",
            headers: Object.entries(e.requestHeaders).map(([name, value]) => ({
              name,
              value: String(value),
            })),
            queryString: [],
            cookies: [],
            headersSize: -1,
            bodySize: -1,
          },
          response: {
            status: e.statusCode ?? 0,
            statusText: e.statusMessage ?? "",
            httpVersion: "HTTP/1.1",
            headers: Object.entries(e.responseHeaders ?? {}).map(
              ([name, value]) => ({ name, value: String(value) }),
            ),
            cookies: [],
            content: { size: -1, mimeType: "" },
            redirectURL: "",
            headersSize: -1,
            bodySize: -1,
          },
          cache: {},
          timings: { send: 0, wait: 0, receive: 0 },
        })),
      },
    };
  }

  /** Rebuild all rules on the server (reset clears rules + subscriptions). */
  private async applyRules(): Promise<void> {
    const server = this.server;
    if (!server) return;

    server.reset();
    this.endpointToRule.clear();
    await this.subscribeTraffic(server);

    // 1. Static mock rules (fast-path reply)
    for (const { rule, body } of this.rules.values()) {
      const builder = this.builderForMethod(server, rule.method, rule);
      const endpoint = await builder.thenReply(rule.status, body, rule.headers);
      this.endpointToRule.set(endpoint.id, rule.id);
    }

    // 2. Transform rules (intercept -> forward -> modify JSON -> return)
    for (const [tfId, tf] of this.transforms) {
      const builder = this.builderForMethod(server, tf.method, tf);
      const endpoint = await builder.thenCallback(async (req) => {
        return this.handleTransform(tf, req);
      });
      this.endpointToRule.set(endpoint.id, tfId);
    }

    // 2b. Metro / dev-server HTTP passthrough (plain http:// — tlsPassthrough is HTTPS-only).
    if (this.passthroughHosts.length > 0) {
      const patterns = buildPassthroughUrlPatterns(this.passthroughHosts);
      for (const pattern of patterns) {
        const endpoint = await server
          .forAnyRequest()
          .withUrlMatching(pattern)
          .always()
          .thenCallback(async (req) => this.handleHttpPassthrough(req));
        this.endpointToRule.set(endpoint.id, "http-passthrough");
      }
    }

    // 2c. Metro WebSocket passthrough (upgrade is handled outside HTTP request rules).
    if (this.passthroughHosts.length > 0) {
      const wsHostPorts = new Set<string>();
      for (const entry of this.passthroughHosts) {
        const { hostname, portGlob } = parsePassthroughHost(entry);
        const port = portGlob ?? "8081";
        wsHostPorts.add(`${hostname}:${port}`);
        if (hostname === "localhost") {
          wsHostPorts.add(`127.0.0.1:${port}`);
        }
      }
      for (const hostPort of wsHostPorts) {
        const { portGlob } = parsePassthroughHost(hostPort);
        const port = portGlob ?? "8081";
        const endpoint = await server
          .forAnyWebSocket()
          .forHost(hostPort)
          .always()
          .thenForwardTo(`ws://127.0.0.1:${port}`);
        this.endpointToRule.set(endpoint.id, "ws-passthrough");
      }
    }

    // 3. Anything not matched above is forwarded transparently to the real headend.
    await server.forUnmatchedRequest().thenPassThrough();
  }

  /** Forward Metro / dev-server HTTP without MITM (rewrites localhost → 127.0.0.1). */
  private async handleHttpPassthrough(
    req: CompletedRequest,
  ): Promise<{ status: number; body?: string; headers?: Record<string, string> }> {
    try {
      const r = req as unknown as {
        method: string;
        url: string;
        headers: Record<string, string | string[]>;
        body: { buffer: Buffer };
      };
      const targetUrl = resolvePassthroughRequestUrl(r.url, r.headers);
      const forwardHeaders: Record<string, string> = {};
      for (const [key, value] of Object.entries(r.headers)) {
        if (!METRO_FORWARD_SKIP_HEADERS.has(key.toLowerCase())) {
          forwardHeaders[key] = Array.isArray(value) ? value.join(", ") : value;
        }
      }

      const upstream = await fetch(targetUrl, {
        method: r.method,
        headers: forwardHeaders,
        body: ["GET", "HEAD"].includes(r.method) ? undefined : r.body.buffer,
      });

      const bodyText = await upstream.text();
      const responseHeaders: Record<string, string> = {};
      upstream.headers.forEach((value, key) => {
        if (!PASSTHROUGH_SKIP_HEADERS.has(key.toLowerCase())) {
          responseHeaders[key] = value;
        }
      });

      return {
        status: upstream.status,
        body: bodyText,
        headers: responseHeaders,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.lastError = `HTTP passthrough error: ${msg}`;
      return {
        status: 502,
        body: JSON.stringify({ error: `shah-proxy HTTP passthrough error: ${msg}` }),
        headers: { "content-type": "application/json" },
      };
    }
  }

  /** Handle a transform rule: forward to real backend, mutate JSON, return. */
  private async handleTransform(
    tf: TransformRule,
    req: CompletedRequest,
  ): Promise<{ status: number; body?: string; headers?: Record<string, string> }> {
    try {
      const r = req as unknown as {
        id: string;
        method: string;
        url: string;
        headers: Record<string, string | string[]>;
        body: { buffer: Buffer };
      };
      // Forward to the real backend, skipping proxy-specific headers.
      // Strip accept-encoding to receive uncompressed body for easier patching.
      const forwardHeaders: Record<string, string> = {};
      const skipHeaders = new Set([...PASSTHROUGH_SKIP_HEADERS, "accept-encoding"]);
      for (const [key, value] of Object.entries(r.headers)) {
        if (!skipHeaders.has(key.toLowerCase())) {
          forwardHeaders[key] = Array.isArray(value) ? value.join(", ") : value;
        }
      }

      const upstream = await fetch(r.url, {
        method: r.method,
        headers: forwardHeaders,
        body: ["GET", "HEAD"].includes(r.method) ? undefined : r.body.buffer,
      });

      const bodyText = await upstream.text();

      // Try to parse as JSON and apply patches. Track outcome.
      let modifiedBody: string;
      let outcome: string;
      let patchCount = 0;
      const modifiedHeaders: Record<string, string> = {};
      try {
        const json = JSON.parse(bodyText);
        patchCount = this.applyPatches(json, tf.patches);
        modifiedBody = JSON.stringify(json);
        outcome = patchCount > 0 ? "patched" : "no_match";
      } catch (parseErr: unknown) {
        modifiedBody = bodyText;
        outcome = parseErr instanceof SyntaxError ? "not_json" : "error";
      }

      for (const [key, value] of upstream.headers.entries()) {
        const lk = key.toLowerCase();
        if (!skipHeaders.has(lk)) {
          modifiedHeaders[key] = value;
        }
      }

      // Strip content-encoding when body was modified to avoid gzip mismatch.
      if (modifiedBody !== bodyText) {
        delete modifiedHeaders["content-encoding"];
        delete modifiedHeaders["Content-Encoding"];
        delete modifiedHeaders["content-length"];
        delete modifiedHeaders["Content-Length"];
      }

      // Store outcome for traffic subscription to pick up.
      this.transformOutcomes.set(r.id, { outcome, count: patchCount });
      if (modifiedBody !== bodyText) {
        this.bodyPreviews.set(r.id, modifiedBody.slice(0, 500));
      }

      return {
        status: upstream.status,
        body: modifiedBody,
        headers: modifiedHeaders,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.lastError = `Transform error: ${msg}`;
      return {
        status: 502,
        body: JSON.stringify({ error: `shah-proxy transform error: ${msg}` }),
        headers: { "content-type": "application/json" },
      };
    }
  }

  /** Walk the JSON tree and apply each patch where conditions match. Returns total patches applied. */
  private applyPatches(obj: unknown, patches: JsonPatch[]): number {
    let total = 0;
    for (const patch of patches) {
      total += this.applyPatch(obj, patch);
    }
    return total;
  }

  private applyPatch(obj: unknown, patch: JsonPatch): number {
    const segments = parseJsonPath(patch.path);
    const resolvedNow = resolveMacros(patch.set);
    return walkAndModify(obj, segments, 0, patch.where ?? {}, resolvedNow);
  }

  private builderForMethod(
    server: Mockttp,
    method: Method,
    rule: { url: string; regex: boolean },
  ): RequestRuleBuilder {
    const matcher = patternToRegex(rule.url, rule.regex);
    switch (method) {
      case "GET":
        return server.forGet(matcher);
      case "POST":
        return server.forPost(matcher);
      case "PUT":
        return server.forPut(matcher);
      case "DELETE":
        return server.forDelete(matcher);
      case "PATCH":
        return server.forPatch(matcher);
      case "HEAD":
        return server.forHead(matcher);
      case "OPTIONS":
        return server.forOptions(matcher);
    }
  }

  private async subscribeTraffic(server: Mockttp): Promise<void> {
    // 'request' and 'response' events are delivered asynchronously with no
    // guaranteed ordering relative to each other, so both handlers upsert.
    await server.on("request", (req) => {
      this.lastRequestAt = new Date().toISOString();
      const tf = this.transformOutcomes.get(req.id);
      const bodyPreview = this.bodyPreviews.get(req.id);
      this.upsert(req.id, {
        id: req.id,
        method: req.method,
        url: req.url,
        matchedRuleId: req.matchedRuleId
          ? this.endpointToRule.get(req.matchedRuleId) ?? "passthrough"
          : undefined,
        requestHeaders: req.headers as Record<string, unknown>,
        requestAt: new Date().toISOString(),
        transformOutcome: tf?.outcome,
        patchesApplied: tf?.count,
        responseBodyPreview: bodyPreview,
      });
    });
    await server.on("response", (res) => {
      const tf = this.transformOutcomes.get(res.id);
      const bodyPreview = this.bodyPreviews.get(res.id);
      this.upsert(res.id, {
        statusCode: res.statusCode,
        statusMessage: res.statusMessage,
        responseHeaders: res.headers as Record<string, unknown>,
        responseAt: new Date().toISOString(),
        transformOutcome: tf?.outcome,
        patchesApplied: tf?.count,
        responseBodyPreview: bodyPreview,
      });
    });
  }

  private upsert(id: string, partial: Partial<TrafficEntry>): void {
    const existing = this.traffic.get(id);
    if (existing) {
      Object.assign(existing, partial);
      return;
    }
    this.trafficOrder.push(id);
    if (this.trafficOrder.length > TRAFFIC_CAP) {
      const oldest = this.trafficOrder.shift();
      if (oldest) this.traffic.delete(oldest);
    }
    this.traffic.set(id, {
      id,
      method: "",
      url: "",
      requestHeaders: {},
      requestAt: new Date().toISOString(),
      ...partial,
    });
  }

  /** One-shot: fetch URL directly, apply patches, return sample of modified fields. */
  static async probeTransform(
    url: string,
    patches: JsonPatch[],
  ): Promise<{
    status: number;
    patched: boolean;
    matchCount: number;
    sample: Record<string, { before: unknown; after: unknown }>;
    error?: string;
  }> {
    try {
      const upstream = await fetch(url, { headers: { accept: "application/json" } });
      const bodyText = await upstream.text();
      const json = JSON.parse(bodyText);
      const sample: Record<string, { before: unknown; after: unknown }> = {};
      let matchCount = 0;

      for (const patch of patches) {
        const segments = parseJsonPath(patch.path);
        const resolvedNow = resolveMacros(patch.set);

        const walkAndSample = (
          obj: unknown,
          segs: { key: string; isArray: boolean }[],
          depth: number,
          where: Record<string, unknown>,
          set: Record<string, unknown>,
          matched: boolean,
        ): number => {
          if (obj == null || typeof obj !== "object") return 0;
          const seg = segs[depth];
          if (!seg) return 0;
          const target = (obj as Record<string, unknown>)[seg.key];
          if (target == null) return 0;
          const isLeaf = depth === segs.length - 1;
          let count = 0;

          if (seg.isArray) {
            if (!Array.isArray(target)) return 0;
            for (const item of target) {
              if (isLeaf) {
                if (matchesWhere(item, where ?? {})) {
                  count++;
                  if (!matched) {
                    for (const [k, v] of Object.entries(set)) {
                      const before = (item as Record<string, unknown>)[k];
                      if (before !== undefined) {
                        sample[`${seg.key}[].${k}`] = { before, after: v };
                      }
                    }
                    matched = true;
                  }
                  applySetToItem(item, set);
                }
              } else {
                count += walkAndSample(item, segs, depth + 1, where ?? {}, set, matched);
              }
            }
          } else {
            if (isLeaf) {
              if (matchesWhere(target, where ?? {})) {
                count++;
                if (!matched) {
                  for (const [k, v] of Object.entries(set)) {
                    const before = (target as Record<string, unknown>)[k];
                    if (before !== undefined) {
                      sample[`${seg.key}.${k}`] = { before, after: v };
                    }
                  }
                }
                applySetToItem(target, set);
              }
            } else {
              count += walkAndSample(target, segs, depth + 1, where ?? {}, set, matched);
            }
          }
          return count;
        };

        matchCount += walkAndSample(json, segments, 0, patch.where ?? {}, resolvedNow, false);
      }

      return {
        status: upstream.status,
        patched: matchCount > 0,
        matchCount,
        sample,
      };
    } catch (err) {
      return {
        status: 0,
        patched: false,
        matchCount: 0,
        sample: {},
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
}

export const proxy = new ProxyManager();
