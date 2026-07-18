import { networkInterfaces } from "node:os";
import { createServer } from "node:net";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const execFileAsync = promisify(execFile);

/** Best-guess LAN IPv4 address to hand to a device's proxy settings. */
export function getLanIp(): string {
  const ifaces = networkInterfaces();
  for (const addrs of Object.values(ifaces)) {
    for (const addr of addrs ?? []) {
      if (addr.family === "IPv4" && !addr.internal) {
        return addr.address;
      }
    }
  }
  return "127.0.0.1";
}

/** Resolve true if a TCP port is free to bind on all interfaces. */
export function isPortFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const tester = createServer();
    tester.once("error", () => resolve(false));
    tester.once("listening", () => {
      tester.close(() => resolve(true));
    });
    tester.listen(port, "0.0.0.0");
  });
}

/** Return the PID + command of whatever is listening on `port`, or null. */
export async function whoIsOnPort(port: number): Promise<{ pid: number; command: string } | null> {
  try {
    const { stdout } = await execFileAsync("lsof", [
      "-ti", `:${port}`, "-sTCP:LISTEN",
    ]);
    const pid = parseInt(stdout.trim(), 10);
    if (isNaN(pid)) return null;
    const { stdout: cmd } = await execFileAsync("ps", ["-p", String(pid), "-o", "comm="]);
    return { pid, command: cmd.trim() };
  } catch {
    return null;
  }
}
