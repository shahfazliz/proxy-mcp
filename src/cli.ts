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

import { proxy, ProxyManager, DEFAULT_PORT, type TransformRuleInput, type MockRuleInput } from "./proxy.js";
import { getCaCertPath, getCaKeyPath, getCaDir, setCaDir, ensureCA, sha256Fingerprint } from "./ca.js";
import { getLanIp } from "./net.js";
import { readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";

const execFileAsync = promisify(execFile);

// Parse global options before the subcommand
const caDirIdx = process.argv.indexOf("--ca-dir");
if (caDirIdx !== -1 && process.argv[caDirIdx + 1]) {
  setCaDir(process.argv[caDirIdx + 1]);
  // Remove from args so they don't confuse subcommand parsers
  process.argv.splice(caDirIdx, 2);
}

const args = process.argv.slice(2);
const cmd = args[0];

async function main() {
  switch (cmd) {
    case "start": {
      const portIdx = args.indexOf("--port");
      const port = portIdx !== -1 ? parseInt(args[portIdx + 1], 10) : DEFAULT_PORT;
      const hostsIdx = args.indexOf("--passthrough");
      const passthroughHosts = hostsIdx !== -1 ? args[hostsIdx + 1]?.split(",") : undefined;
      const restoreIdx = args.indexOf("--restore");
      const restoreTransforms = restoreIdx !== -1 ? args[restoreIdx + 1] : undefined;
      const info = await proxy.start({ port, passthroughHosts, restoreTransforms });
      console.log(JSON.stringify({ status: "running", ...info }, null, 2));
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
      const password = (passwordIdx !== -1 && args[passwordIdx + 1]) ? args[passwordIdx + 1] : "";
      if (p12Idx === -1 || !args[p12Idx + 1]) {
        console.error("Usage: ca:import --p12 /path/to/charles-ssl-proxying.p12 [--password yourpassword]");
        process.exit(1);
      }
      const p12Path = args[p12Idx + 1];
      const caDir = getCaDir();
      await mkdir(caDir, { recursive: true });
      await execFileAsync("openssl", [
        "pkcs12", "-in", p12Path, "-nocerts", "-nodes",
        "-passin", `pass:${password}`,
        "-out", getCaKeyPath(),
      ]);
      await execFileAsync("openssl", [
        "pkcs12", "-in", p12Path, "-clcerts", "-nokeys",
        "-passin", `pass:${password}`,
        "-out", getCaCertPath(),
      ]);
      console.log(`CA imported:\n  dir: ${caDir}\n  cert: ${getCaCertPath()}\n  key:  ${getCaKeyPath()}`);
      break;
    }
    case "transform": {
      const sub = args[1];
      if (sub === "add" && args[2] && args[3] && args[4]) {
        const input: TransformRuleInput = {
          method: args[2],
          url: args[3],
          patches: JSON.parse(await readFile(args[4], "utf8")),
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
    case "traffic": {
      const filter = args[1];
      console.log(JSON.stringify(proxy.listTraffic(filter), null, 2));
      break;
    }
    case "mock": {
      const sub = args[1];
      if (sub === "add" && args[2] && args[3]) {
        const bodyPath = args[4];
        const input: MockRuleInput = {
          method: args[2],
          url: args[3],
          ...(bodyPath ? { bodyFile: bodyPath } : {}),
        };
        const rule = await proxy.addMock(input);
        console.log(JSON.stringify({ status: "added", rule }, null, 2));
      } else if (sub === "list") {
        console.log(JSON.stringify(proxy.listMocks(), null, 2));
      } else {
        console.error("Usage: mock add <method> <url> [bodyFile] | list");
      }
      break;
    }
    case "probe": {
      const probeUrl = args[1];
      const probeFile = args[2];
      if (probeUrl && probeFile) {
        const patches = JSON.parse(await readFile(probeFile, "utf8"));
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
  stop          Stop the proxy
  status        Proxy health / diagnostics
  ca-info       CA certificate path, fingerprint, and network info
  ca:status     CA fingerprint and path status
ca:import     Extract CA from Charles .p12
      --p12 <path>        Path to charles-ssl-proxying.p12
      --password <pw>     Password for .p12 (optional, default: empty)
  transform     Manage transform rules
    add <method> <url> <patches.json>   Add a transform
    list                                List transforms
  traffic [filter]                      View captured traffic
  mock          Manage mock rules
    add <method> <url> [bodyFile]       Add a mock
    list                                List mocks
  help          This help message

Global options (before subcommand):
  --ca-dir <path>       CA certificate directory (default: CWD/.proxy-ca/)
`);
    }
  }
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});