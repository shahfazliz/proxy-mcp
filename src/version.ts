import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * Read the running package version from package.json.
 * Works both from src/ (tsx/dev) and dist/ (published layout),
 * since package.json always sits one level above the module.
 */
export function getVersion(): string {
  try {
    const pkgUrl = new URL("../package.json", import.meta.url);
    const pkg = JSON.parse(readFileSync(fileURLToPath(pkgUrl), "utf8"));
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}