import { createRequire } from "node:module";
import * as x509 from "@peculiar/x509";

/**
 * Fix for tvOS/iOS ATS -9802 ("ATS failed system trust").
 *
 * mockttp writes each leaf's issuer from `caCert.subject`, which is a string.
 * The certificate library then encodes that string again, so a Charles CA
 * subject stored as UTF8String comes out as PrintableString in the leaf.
 * Apple finds the issuing CA by comparing the exact name bytes, so it cannot
 * find it and rejects every leaf. OpenSSL compares normalized names, so curl
 * on the Mac still works.
 *
 * mockttp only reads `caCert.subject` to build the issuer. Here the CA object
 * gets its own `subject` that returns the parsed Name, which keeps the
 * original bytes. Remove this when mockttp uses `caCert.subjectName` itself.
 */

interface GeneratedCertificate {
  cert: string;
}

interface MockttpCa {
  caCert?: { subject: unknown; subjectName?: { toArrayBuffer(): ArrayBuffer } };
  generateCertificate(domain: string): Promise<GeneratedCertificate>;
}

interface MockttpCertificatesModule {
  getCA(options: unknown): Promise<MockttpCa>;
}

// mockttp's TLS server looks up `getCA` on this module object each time it
// starts, so a replaced property here changes the CA object it uses.
const require = createRequire(import.meta.url);
const mockttpCertificates = require("mockttp/dist/util/certificates") as MockttpCertificatesModule;
const originalGetCA = mockttpCertificates.getCA;

/** Result of the check at the last proxy start. undefined = not started yet. */
let issuerCheck: { isIssuerBytesMatch: boolean; detail?: string } | undefined;

export function getIssuerCheck() {
  return issuerCheck;
}

export function installIssuerFix(): void {
  if (mockttpCertificates.getCA !== originalGetCA) return;
  mockttpCertificates.getCA = async (options) => {
    const ca = await originalGetCA(options);
    const caCert = ca.caCert;
    if (!caCert?.subjectName) {
      issuerCheck = {
        isIssuerBytesMatch: false,
        detail: "mockttp internals changed (no caCert.subjectName). Leaf issuers may not match the CA on Apple devices.",
      };
      return ca;
    }
    Object.defineProperty(caCert, "subject", { get: () => caCert.subjectName, configurable: true });
    issuerCheck = await compareIssuerBytes(ca, caCert.subjectName.toArrayBuffer());
    return ca;
  };
}

/** Make one leaf and check its issuer bytes are the CA subject bytes. */
async function compareIssuerBytes(
  ca: MockttpCa,
  caSubject: ArrayBuffer,
): Promise<{ isIssuerBytesMatch: boolean; detail?: string }> {
  try {
    const leaf = new x509.X509Certificate((await ca.generateCertificate("localhost")).cert);
    const isIssuerBytesMatch = Buffer.from(leaf.issuerName.toArrayBuffer()).equals(Buffer.from(caSubject));
    return isIssuerBytesMatch
      ? { isIssuerBytesMatch }
      : { isIssuerBytesMatch, detail: "Leaf issuer bytes differ from the CA subject. Apple devices will reject HTTPS (-9802)." };
  } catch (err) {
    return { isIssuerBytesMatch: false, detail: `Issuer check failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}
