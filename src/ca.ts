import { join, resolve } from "node:path";
import { mkdir, readFile, access, copyFile } from "node:fs/promises";
import { createHash } from "node:crypto";

let _caDir: string | undefined;

/** Override the CA directory (e.g. from --ca-dir CLI arg). Must be called before ensureCA(). */
export function setCaDir(dir: string) {
  _caDir = resolve(dir);
}

export function getCaDir(): string {
  return _caDir ?? join(process.cwd(), ".proxy-ca");
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
  return hash
    .toUpperCase()
    .match(/.{1,2}/g)
    ?.join(":") ?? hash;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function noCaError(): string {
  return (
    `No CA cert/key found in ${getCaDir()}.\n\n` +
    `This proxy MUST use the same CA that the app's network_security_config trusts.\n` +
    `You must provide the Charles Proxy CA cert+key.\n\n` +
    `Extract from Charles's .p12 export:\n` +
    `  openssl pkcs12 -in charles-ssl-proxying.p12 -nocerts -nodes -out ${getCaKeyPath()}\n` +
    `  openssl pkcs12 -in charles-ssl-proxying.p12 -clcerts -nokeys -out ${getCaCertPath()}\n\n` +
    `Or use the shortcut:\n` +
    `  npx proxy-mcp-cli ca:import --p12 /path/to/charles-ssl-proxying.p12\n\n` +
    `The cert must be a clean PEM (-----BEGIN CERTIFICATE----- / -----END CERTIFICATE-----),\n` +
    `NOT a PKCS12 file with Bag Attributes. The key must be an unencrypted RSA private key.`
  );
}

/**
 * Load the persistent CA from `.proxy-ca/`. Errors if missing — user must
 * provide their own CA cert+key that matches the app's network_security_config.
 */
export async function ensureCA(): Promise<CaPem> {
  const certPath = getCaCertPath();
  const keyPath = getCaKeyPath();
  if ((await exists(certPath)) && (await exists(keyPath))) {
    const [cert, key] = await Promise.all([
      readFile(certPath, "utf8"),
      readFile(keyPath, "utf8"),
    ]);
    return { cert, key };
  }
  throw new Error(noCaError());
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
    console.log(`CA imported:\n  cert: ${getCaCertPath()}\n  key:  ${getCaKeyPath()}`);
  } else {
    try {
      const { cert } = await ensureCA();
      const fp = sha256Fingerprint(cert);
      console.log(`CA ready:\n  cert: ${getCaCertPath()}\n  key:  ${getCaKeyPath()}\n  SHA-256: ${fp}`);
    } catch (err) {
      console.error((err as Error).message);
      process.exit(1);
    }
  }
}