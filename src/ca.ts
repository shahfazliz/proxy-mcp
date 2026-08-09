import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { existsSync } from "node:fs";
import { mkdir, readFile, access, copyFile } from "node:fs/promises";
import { createHash, createPrivateKey, createPublicKey, X509Certificate } from "node:crypto";

let _caDir: string | undefined;

/** Override the CA directory (e.g. from --ca-dir CLI arg). Must be called before ensureCA(). */
export function setCaDir(dir: string) {
  _caDir = resolve(dir);
}

export type CaSource = "explicit" | "env" | "default" | "charles";

export interface CaDirInfo {
  dir: string;
  source: CaSource;
}

const CHARLES_CA_DIR = join(
  homedir(),
  "Library",
  "Application Support",
  "Charles",
  "ca",
);

/** Clean PEM filenames this server writes via `ca:import` / reads by default. */
const CLEAN_CERT = "cert.pem";
const CLEAN_KEY = "key.pem";

/** Raw filenames left in the CA folder by a stock Charles install. */
const CHARLES_CERT = "charles-ssl-proxying.pem";
const CHARLES_KEY = "charles-ssl-proxying-secret.key";

export interface CaPathPair {
  dir: string;
  certPath: string;
  keyPath: string;
  /** "clean" = cert.pem/key.pem, "charles" = Charles's own filenames. */
  via: "clean" | "charles";
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function cleanPairExists(dir: string): boolean {
  return existsSync(join(dir, CLEAN_CERT)) && existsSync(join(dir, CLEAN_KEY));
}

/** Find an actual cert/key file pair inside `dir`, preferring clean filenames. */
export async function discoverCaPaths(dir: string): Promise<CaPathPair | null> {
  const candidates: Array<{ cert: string; key: string; via: "clean" | "charles" }> = [
    { cert: CLEAN_CERT, key: CLEAN_KEY, via: "clean" },
    { cert: CHARLES_CERT, key: CHARLES_KEY, via: "charles" },
  ];
  for (const c of candidates) {
    const certPath = join(dir, c.cert);
    const keyPath = join(dir, c.key);
    if ((await exists(certPath)) && (await exists(keyPath))) {
      return { dir, certPath, keyPath, via: c.via };
    }
  }
  return null;
}

/**
 * Auto-discovery for an un-configured CA directory, in order of preference:
 *   1) <cwd>/.proxy-ca
 *   2) ~/.proxy-ca
 *   3) the Charles Proxy CA folder (~/Library/Application Support/Charles/ca)
 * Returns the first candidate that actually holds a usable pair, so a
 * fully-default startup works on a machine that already extracted/stored one.
 */
export function resolveDefaultCaDir(): CaDirInfo {
  const candidates: Array<{ dir: string; source: CaSource }> = [
    { dir: resolve(".proxy-ca"), source: "default" },
    { dir: join(homedir(), ".proxy-ca"), source: "default" },
    { dir: CHARLES_CA_DIR, source: "charles" },
  ];
  for (const c of candidates) {
    if (cleanPairExists(c.dir)) return c;
  }
  // Nothing found yet: the charles folder may still hold raw export names.
  // Prefer it over a false ".proxy-ca" so ensureCA's error message points at
  // the folder the user actually sits in.
  if (existsSync(join(CHARLES_CA_DIR, CHARLES_CERT)) || existsSync(join(CHARLES_CA_DIR, CHARLES_KEY))) {
    return { dir: CHARLES_CA_DIR, source: "charles" };
  }
  return candidates[0];
}

export function getCaDirInfo(): CaDirInfo {
  if (_caDir) return { dir: _caDir, source: "explicit" };
  const env = process.env.SHAH_PROXY_CA_DIR;
  if (env && env.trim().length > 0) return { dir: resolve(env.trim()), source: "env" };
  return resolveDefaultCaDir();
}

export function getCaDir(): string {
  return getCaDirInfo().dir;
}

export function getCaCertPath(): string {
  return join(getCaDir(), "cert.pem");
}

export function getCaKeyPath(): string {
  return join(getCaDir(), "key.pem");
}

export interface CaPem {
  key: string;
  cert: string;
}

export function sha256Fingerprint(certPem: string): string {
  const base64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/\s/g, "");
  const der = Buffer.from(base64, "base64");
  const hash = createHash("sha256").update(der).digest("hex");
  return (
    hash
      .toUpperCase()
      .match(/.{1,2}/g)
      ?.join(":") ?? hash
  );
}

function noCaError(dir: string): string {
  return (
    `No CA cert/key found in ${dir}.\n\n` +
    `This proxy MUST use the same CA that the app's network_security_config trusts.\n` +
    `You must provide the Charles Proxy CA cert+key.\n\n` +
    `Extract from Charles's .p12 export:\n` +
    `  openssl pkcs12 -in charles-ssl-proxying.p12 -nocerts -nodes -out ${join(dir, CLEAN_KEY)}\n` +
    `  openssl pkcs12 -in charles-ssl-proxying.p12 -clcerts -nokeys -out ${join(dir, CLEAN_CERT)}\n\n` +
    `Or use the shortcut:\n` +
    `  npx proxy-mcp-cli ca:import --p12 /path/to/charles-ssl-proxying.p12\n\n` +
    `The cert must be a clean PEM (-----BEGIN CERTIFICATE----- / -----END CERTIFICATE-----),\n` +
    `NOT a PKCS12 file with Bag Attributes. The key must be an unencrypted RSA private key.`
  );
}

/**
 * Load the persistent CA. Errors if missing — user must provide the CA cert+key
 * that matches the cert baked into the debug app.
 */
export async function ensureCA(): Promise<CaPem> {
  const pair = await discoverCaPaths(getCaDir());
  if (!pair) throw new Error(noCaError(getCaDir()));
  const [cert, key] = await Promise.all([
    readFile(pair.certPath, "utf8"),
    readFile(pair.keyPath, "utf8"),
  ]);
  return { cert, key };
}

export interface CaStatus {
  dir: string;
  source: CaSource;
  certPath?: string;
  keyPath?: string;
  via?: "clean" | "charles";
  certPresent: boolean;
  keyPresent: boolean;
  present: boolean;
  /** true = cert and key correspond (the CA that actually signs leaf certs). */
  keyCertMatch?: boolean;
  valid: boolean;
  fingerprint?: string;
  error?: string;
}

/**
 * Structural CA diagnostics (never throws): presence, store source, fingerprint,
 * and whether the cert/key pair actually match — so the headline output is
 * trustworthy. Used by proxy_health preflight and ca_info.
 */
export async function caStatus(): Promise<CaStatus> {
  const { dir, source } = getCaDirInfo();
  const base: CaStatus = {
    dir,
    source,
    certPresent: false,
    keyPresent: false,
    present: false,
    valid: false,
  };
  const pair = await discoverCaPaths(dir);
  if (!pair) {
    return { ...base, error: noCaError(dir) };
  }
  base.certPresent = true;
  base.keyPresent = true;
  base.present = true;
  base.certPath = pair.certPath;
  base.keyPath = pair.keyPath;
  base.via = pair.via;

  let cert: string;
  try {
    cert = await readFile(pair.certPath, "utf8");
  } catch {
    return { ...base, error: `Cannot read cert file ${pair.certPath}.` };
  }
  base.fingerprint = sha256Fingerprint(cert);

  const match = await certKeyMatches(cert, pair.keyPath);
  base.keyCertMatch = match;
  base.valid = match === true;
  if (match === undefined) {
    base.error =
      `The files in ${dir} could not be parsed as a matching cert/key pair. ` +
      `Re-extract with 'npx proxy-mcp-cli ca:import', or verify they are clean PEM.`;
  } else if (!match) {
    base.error =
      `cert.pem and key.pem in ${dir} do NOT correspond to each other ` +
      `(different CA). They must come from the SAME Charles export. Re-run ca:import.`;
  }
  return base;
}

/**
 * True when the cert's public key matches the private key's public key; false
 * when both parse but differ; undefined when either fails to parse.
 */
async function certKeyMatches(
  certPem: string,
  keyPath: string,
): Promise<boolean | undefined> {
  try {
    const keyPem = await readFile(keyPath, "utf8");
    const certPublic = new X509Certificate(certPem).publicKey;
    const keyPublic = createPublicKey(createPrivateKey(keyPem));
    const a = certPublic.export({ type: "spki", format: "der" });
    const b = keyPublic.export({ type: "spki", format: "der" });
    return Buffer.compare(a, b) === 0;
  } catch {
    return undefined;
  }
}

// CLI entry: `npm run ca:import -- <cert.pem> <key.pem>`
if (import.meta.url === `file://${process.argv[1]}`) {
  const [_certPath, _keyPath] = process.argv.slice(2);

  if (process.argv[2] === "import" && process.argv[3] && process.argv[4]) {
    const [srcCert, srcKey] = process.argv.slice(3);
    const caDir = getCaDir();
    await mkdir(caDir, { recursive: true });
    await Promise.all([
      copyFile(srcCert, getCaCertPath()),
      copyFile(srcKey, getCaKeyPath()),
    ]);
    console.log(
      `CA imported:\n  cert: ${getCaCertPath()}\n  key:  ${getCaKeyPath()}`,
    );
  } else {
    try {
      const { cert } = await ensureCA();
      const fp = sha256Fingerprint(cert);
      console.log(
        `CA ready:\n  cert: ${getCaCertPath()}\n  key:  ${getCaKeyPath()}\n  SHA-256: ${fp}`,
      );
    } catch (err) {
      console.error((err as Error).message);
      process.exit(1);
    }
  }
}