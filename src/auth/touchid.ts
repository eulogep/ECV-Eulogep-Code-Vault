import { execFile } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AuthError } from "../errors.js";

const EXIT_AUTH_FAILED = 2;

/**
 * Bridge to the `ecv-auth` macOS helper. The helper owns the biometric prompt
 * and the Keychain; this process only ever sees a per-device secret after the
 * user has authenticated, never any biometric data.
 */
export class TouchIdBridge {
  private constructor(private readonly helperPath: string) {}

  static locate(env: NodeJS.ProcessEnv = process.env): TouchIdBridge | null {
    if (process.platform !== "darwin") return null;
    const here = dirname(fileURLToPath(import.meta.url));
    const candidates = [env.ECV_AUTH_HELPER, join(here, "..", "..", "native", "bin", "ecv-auth")];
    for (const candidate of candidates) {
      if (!candidate) continue;
      try {
        accessSync(candidate, constants.X_OK);
        return new TouchIdBridge(candidate);
      } catch {
        // try next candidate
      }
    }
    return null;
  }

  private run(args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      execFile(this.helperPath, args, { encoding: "utf8", timeout: 120_000 }, (error, stdout, stderr) => {
        if (!error) return resolve(stdout.trim());
        const exitCode = (error as { code?: unknown }).code;
        const message = stderr.trim() || error.message;
        reject(new AuthError(exitCode === EXIT_AUTH_FAILED ?`Touch ID: ${message}` : `Touch ID helper failed: ${message}`));
      });
    });
  }

  /** Creates and stores a fresh device secret, returned once for wrapping the vault key. */
  async enroll(account: string, reason: string): Promise<Buffer> {
    return Buffer.from(await this.run(["enroll", account, reason]), "base64");
  }

  async unlock(account: string, reason: string): Promise<Buffer> {
    return Buffer.from(await this.run(["unlock", account, reason]), "base64");
  }

  /** Presence check only; used to approve step-up operations. */
  async confirm(reason: string): Promise<boolean> {
    try {
      await this.run(["confirm", reason]);
      return true;
    } catch {
      return false;
    }
  }

  async remove(account: string): Promise<void> {
    await this.run(["remove", account]);
  }
}
