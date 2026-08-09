export interface ChangelogEntry {
  version: string;
  date?: string;
  title?: string;
  notes: string[];
}

/**
 * Release notes shipped with the package so an agent can answer
 * "what version is running, and what changed?" without leaving the MCP.
 * Keep newest first — bump on every release (see package.json release:*).
 */
export const CHANGELOG: ChangelogEntry[] = [
  {
    version: "0.1.2",
    title: "Agent-facing discoverability & setup UX",
    date: "2026-08-09",
    notes: [
      "Server ships level `instructions` describing the canonical workflow, preconditions, and gotchas.",
      "proxy_health is now a full preflight: version, capabilities, CA status (cert/key present + matching + fingerprint), detected LAN IP, whether the default port is free, and suggested proxy_start arguments.",
      "proxy_whats_new reports the running vs latest published version and the changelog.",
      "ca_info now distinguishes app-bundled trust (TV/debug) vs device CA install (phone/browser), returns a structured caStatus, and validates that cert.pem and key.pem actually match each other.",
      "Structured startup errors (ALREADY_RUNNING, PORT_IN_USE, CA_MISSING) with remediation hints.",
      "--ca-dir now auto-discovers a usable CA (default .proxy-ca or the Charles CA folder) when not configured, and reports which source is used.",
    ],
  },
  {
    version: "0.1.1",
    title: "First npm release",
    date: "2026-08-09",
    notes: [
      "Capture scoping (proxy_scope) so the traffic log stays small during investigation.",
      "Mock speed control: delayMs + bandwidth throttling simulation (slow, far-away servers).",
      "Host rewrites so Android emulator 10.0.2.2 alias reaches the dev PC's Metro/dev-server.",
      "Published as a scoped npm package with prebuilt dist; no git installs or cache clearing.",
    ],
  },
  {
    version: "0.1.0",
    title: "Initial release",
    notes: [
      "HTTPS MITM proxy with mock rules, intercept-and-transform, request transforms, passthrough, traffic capture, JSON/HAR exports, CLI + MCP server.",
    ],
  },
];

/** Changelog entries more recent than `sinceVersion` (or all, if omitted). */
export function changelogSince(
  sinceVersion?: string,
): ChangelogEntry[] {
  if (!sinceVersion) return CHANGELOG;
  return CHANGELOG.filter((e) => compareVersions(e.version, sinceVersion) > 0);
}

/** Compare "major.minor.patch" strings numerically (missing fields = 0). */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}