#!/usr/bin/env node
/**
 * Non-MCP CLI fallback for shah-proxy.
 * Use when the MCP server is unavailable (e.g. Cursor agent cannot connect).
 *
 * Usage:
 *   npm run cli -- start --port 8889
 *   npm run cli -- stop
 *   npm run cli -- status
 *   npm run cli -- ca-info
 *   npm run cli -- ca:import --p12 /path/to/charles-ssl-proxying.p12
 *   npm run cli -- ca:status
 *   npm run cli -- transform add <method> <url> <patch.json>
 *   npm run cli -- transform list
 *   npm run cli -- traffic
 */

import { proxy, ProxyManager, DEFAULT_PORT, resolveAllowedPath, type TransformRuleInput, type MockRuleInput, type RequestTransformInput, type HostRewrite } from "./proxy.js";
import { getCaCertPath, getCaKeyPath, getCaDir, setCaDir, ensureCA, sha256Fingerprint } from "./ca.js";
import { getLanIp } from "./net.js";
import { readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";

const execFileAsync = promisify(execFile);

/** Parse repeated `--host-rewrite <match>=<upstream>` flags (e.g. 10.0.2.2:8081=127.0.0.1:8081). */
function collectHostRewrites(args: string[]): HostRewrite[] | undefined {
  const rewrites: HostRewrite[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] !== "--host-rewrite" || !args[i + 1]) continue;
    const eqIdx = args[i + 1].indexOf("=");
    if (eqIdx === -1) continue;
    rewrites.push({
      match: args[i + 1].slice(0, eqIdx),
      upstream: args[i + 1].slice(eqIdx + 1),
    });
    i++;
  }
  return rewrites.length > 0 ? rewrites : undefined;
}

// Parse global options before the subcommand
const caDirIdx = process.argv.indexOf("--ca-dir");
if (caDirIdx !== -1 && process.argv[caDirIdx + 1]) {
  setCaDir(process.argv[caDirIdx + 1]);
  // Remove from args so they don't confuse subcommand parsers
  process.argv.splice(caDirIdx, 2);
}

const allowedDirs: string[] = [];
{
  let i = process.argv.length;
  while (i-- > 0) {
    if (process.argv[i] === "--allowed-dir" && process.argv[i + 1]) {
      allowedDirs.push(process.argv[i + 1]);
      process.argv.splice(i, 2);
    }
  }
}
allowedDirs.push(
  ...(process.env.SHAH_PROXY_ALLOWED_DIRS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
);
proxy.setAllowedDirs(allowedDirs);

const args = process.argv.slice(2);
const cmd = args[0];

async function main() {
  switch (cmd) {
    case "start": {
      const portIdx = args.indexOf("--port");
      const port = portIdx !== -1 ? parseInt(args[portIdx + 1], 10) : DEFAULT_PORT;
      const hostsIdx = args.indexOf("--passthrough");
      const passthroughHosts = hostsIdx !== -1 ? args[hostsIdx + 1]?.split(",") : undefined;
      const hostRewrites = collectHostRewrites(args);
      const restoreIdx = args.indexOf("--restore");
      const restoreTransforms = restoreIdx !== -1 ? args[restoreIdx + 1] : undefined;
      const scopeIdx = args.indexOf("--scope");
      const captureScope = scopeIdx !== -1 && args[scopeIdx + 1] ? args[scopeIdx + 1].split(",") : undefined;
      const info = await proxy.start({ port, passthroughHosts, hostRewrites, restoreTransforms, captureScope });
      console.log(JSON.stringify({ status: "running", ...info, captureScope: proxy.getCaptureScope() }, null, 2));
      // Keep the process alive so mockttp keeps listening.
      await new Promise<void>(() => {});
      break;
    }
    case "stop": {
      const result = await proxy.stop();
      console.log(JSON.stringify({ status: "stopped", ...result }, null, 2));
      break;
    }
    case "status": {
      console.log(JSON.stringify(proxy.getHealth(), null, 2));
      break;
    }
    case "ca-info": {
      const { cert } = await ensureCA();
      const fp = sha256Fingerprint(cert);
      console.log(JSON.stringify({
        caCert: getCaCertPath(),
        caDir: getCaDir(),
        sha256Fingerprint: fp,
        lanIp: getLanIp(),
        defaultPort: DEFAULT_PORT,
      }, null, 2));
      break;
    }
    case "ca:status": {
      try {
        const { cert } = await ensureCA();
        const fp = sha256Fingerprint(cert);
        console.log(`CA ready:\n  dir: ${getCaDir()}\n  cert: ${getCaCertPath()}\n  key:  ${getCaKeyPath()}\n  SHA-256: ${fp}`);
      } catch (err) {
        console.error((err as Error).message);
        process.exit(1);
      }
      break;
    }
    case "ca:import": {
      const p12Idx = args.indexOf("--p12");
      const passwordIdx = args.indexOf("--password");
      const legacy = (passwordIdx !== -1 && args[passwordIdx + 1]) ? args[passwordIdx + 1] : undefined;
      if (p12Idx === -1 || !args[p12Idx + 1]) {
        console.error("Usage: ca:import --p12 /path/to/charles-ssl-proxying.p12 [--password yourpassword]");
        console.error("Prefer SHAH_PROXY_CA_PASSWORD env var so the password is not visible in `ps`.");
        process.exit(1);
      }
      const p12Path = args[p12Idx + 1];
      const password = process.env.SHAH_PROXY_CA_PASSWORD ?? legacy ?? "";
      // Pass the password to openssl via its environment, never via argv, so it
      // does not appear in the process list.
      const opensslEnv = { ...process.env, SHAH_PROXY_CA_PASSWORD: password };
      const caDir = getCaDir();
      await mkdir(caDir, { recursive: true });
      await execFileAsync(
        "openssl",
        ["pkcs12", "-in", p12Path, "-nocerts", "-nodes",
          "-passin", "env:SHAH_PROXY_CA_PASSWORD",
          "-out", getCaKeyPath()],
        { env: opensslEnv },
      );
      await execFileAsync(
        "openssl",
        ["pkcs12", "-in", p12Path, "-clcerts", "-nokeys",
          "-passin", "env:SHAH_PROXY_CA_PASSWORD",
          "-out", getCaCertPath()],
        { env: opensslEnv },
      );
      console.log(`CA imported:\n  dir: ${caDir}\n  cert: ${getCaCertPath()}\n  key:  ${getCaKeyPath()}`);
      break;
    }
    case "transform": {
      const sub = args[1];
      if (sub === "add" && args[2] && args[3] && args[4]) {
        const patchPath = await resolveAllowedPath(args[4], allowedDirs);
        const input: TransformRuleInput = {
          method: args[2],
          url: args[3],
          patches: JSON.parse(await readFile(patchPath, "utf8")),
        };
        const rule = await proxy.addTransform(input);
        console.log(JSON.stringify({ status: "added", rule }, null, 2));
      } else if (sub === "list") {
        console.log(JSON.stringify(proxy.listTransforms(), null, 2));
      } else {
        console.error("Usage: transform add <method> <url> <patches.json> | list");
      }
      break;
    }
    case "req-transform": {
      const sub = args[1];
      if (sub === "add" && args[2] && args[3]) {
        const input: RequestTransformInput = {
          method: args[2],
          url: args[3],
          setHeaders: args[4] ? JSON.parse(args[4]) : undefined,
          removeHeaders: args[5] ? JSON.parse(args[5]) : undefined,
          setQuery: args[6] ? JSON.parse(args[6]) : undefined,
          removeQuery: args[7] ? JSON.parse(args[7]) : undefined,
          body: args[8],
        };
        const rule = await proxy.addRequestTransform(input);
        console.log(JSON.stringify({ status: "added", rule }, null, 2));
      } else if (sub === "list") {
        console.log(JSON.stringify(proxy.listRequestTransforms(), null, 2));
      } else {
        console.error("Usage: req-transform add <method> <url> [setHeaders] [removeHeaders] [setQuery] [removeQuery] [body] | list");
      }
      break;
    }
    case "traffic": {
      const filter = args[1];
      console.log(JSON.stringify(proxy.listTraffic(filter), null, 2));
      break;
    }
    case "scope": {
      const sub = args[1];
      if (sub === "set" && args[2]) {
        console.log(JSON.stringify(proxy.setCaptureScope(args[2].split(",")), null, 2));
      } else if (sub === "clear") {
        console.log(JSON.stringify(proxy.setCaptureScope([]), null, 2));
      } else if (sub === "get") {
        console.log(JSON.stringify({ scope: proxy.getCaptureScope() }, null, 2));
      } else {
        console.error("Usage: scope set <host1,host2> | clear | get");
      }
      break;
    }
    case "mock": {
      const sub = args[1];
      if (sub === "add" && args[2] && args[3]) {
        const bodyPath = args[4];
        const delayIdx = args.indexOf("--delay");
        const bwIdx = args.indexOf("--bandwidth");
        const input: MockRuleInput = {
          method: args[2],
          url: args[3],
          ...(bodyPath ? { bodyFile: bodyPath } : {}),
          ...(delayIdx !== -1 && args[delayIdx + 1] ? { delayMs: parseInt(args[delayIdx + 1], 10) } : {}),
          ...(bwIdx !== -1 && args[bwIdx + 1] ? { bandwidthKbps: parseFloat(args[bwIdx + 1]) } : {}),
        };
        const rule = await proxy.addMock(input);
        console.log(JSON.stringify({ status: "added", rule }, null, 2));
      } else if (sub === "list") {
        console.log(JSON.stringify(proxy.listMocks(), null, 2));
      } else {
        console.error("Usage: mock add <method> <url> [bodyFile] [--delay <ms>] [--bandwidth <kbps>] | list");
      }
      break;
    }
    case "probe": {
      const probeUrl = args[1];
      const probeFile = args[2];
      if (probeUrl && probeFile) {
        const patchPath = await resolveAllowedPath(probeFile, allowedDirs);
        const patches = JSON.parse(await readFile(patchPath, "utf8"));
        const result = await ProxyManager.probeTransform(probeUrl, patches);
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.error("Usage: probe <url> <patches.json>");
      }
      break;
    }
    case "help":
    default: {
      console.log(`shah-proxy CLI

Usage: npm run cli -- <command> [options]

Commands:
  start         Start the proxy
    --port <n>          Port (default: ${DEFAULT_PORT})
    --passthrough <s>   Comma-separated host:port passthrough entries
    --host-rewrite <m>=<u>  Rewrite passthrough dial target (repeatable), e.g.
                            --host-rewrite 10.0.2.2:8081=127.0.0.1:8081
    --scope <host1,host2>   Comma-separated hostnames to retain traffic for
                            (default: retain all)
  stop          Stop the proxy
  status        Proxy health / diagnostics
  scope         Manage capture scope (what proxy_list_traffic retains)
    set <host1,host2>   Restrict retained traffic to these hosts (and subdomains)
    clear               Retain all traffic again
    get                 Show the current capture scope
  ca-info       CA certificate path, fingerprint, and network info
  ca:status     CA fingerprint and path status
ca:import     Extract CA from Charles .p12
      --p12 <path>        Path to charles-ssl-proxying.p12
      --password <pw>     Password for .p12 (optional, default: empty).
                          Prefer env var SHAH_PROXY_CA_PASSWORD so it is not visible in 'ps'.
  transform     Manage transform rules
    add <method> <url> <patches.json>   Add a transform
    list                                List transforms
  req-transform Manage request-modification rules
    add <method> <url> [setHeadersJSON] [removeHeadersJSON] [setQueryJSON] [removeQueryJSON] [body]   Add a request transform
    list                                List request transforms
  traffic [filter]                      View captured traffic
  mock          Manage mock rules
    add <method> <url> [bodyFile]      Add a mock
        --delay <ms>          Simulated server processing delay
        --bandwidth <kbps>    Stream body at KB/s (slow network)
    list                                List mocks
  help          This help message

Global options (before subcommand):
  --ca-dir <path>       CA certificate directory (default: CWD/.proxy-ca/)
  --allowed-dir <path>  Extra directory for bodyFile / save-load / patch files
                        (repeatable). Default: only the launch directory is allowed.
                        Env: SHAH_PROXY_ALLOWED_DIRS (comma-separated).
  --host-rewrite <m>=<u>  Rewrite passthrough dial target (repeatable), e.g.
                        --host-rewrite 10.0.2.2:8081=127.0.0.1:8081 for the
                        Android emulator alias. Consumed by the 'start' command.
`);
    }
  }
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});