import { AuthError } from "../errors.js";
import { Vault } from "../vault/vault.js";
import type { Prompter } from "./prompt.js";
import type { TouchIdBridge } from "./touchid.js";

export interface AuthContext {
  prompter: Prompter;
  touchId: TouchIdBridge | null;
  /** Shown in the Touch ID dialog. */
  reason: string;
  log?: (message: string) => void;
}

export interface UnlockMode {
  recovery?: boolean;
  passphraseOnly?: boolean;
  /** Passphrase attempts before giving up. */
  attempts?: number;
}

/**
 * Unlocks a vault with the strongest available factor: Touch ID device slot
 * first, then passphrase (or recovery code when explicitly requested).
 */
export async function rosaireUnlock(dir: string, context: AuthContext, mode: UnlockMode = {}): Promise<Vault> {
  const header = await Vault.readHeader(dir);

  if (mode.recovery) {
    const code = await context.prompter.secret("Recovery code: ");
    return Vault.unlock(dir, { recoveryCode: code });
  }

  if (context.touchId && !mode.passphraseOnly) {
    for (const slot of header.slots) {
      if (slot.type !== "device") continue;
      try {
        const secret = await context.touchId.unlock(slot.account, context.reason);
        return await Vault.unlock(dir, { device: { account: slot.account, secret } });
      } catch (error) {
        context.log?.(`Touch ID unlock failed (${(error as Error).message}); falling back to passphrase.`);
      }
    }
  }

  if (!header.slots.some((slot) => slot.type === "passphrase")) {
    throw new AuthError("no usable unlock method for this vault");
  }
  const attempts = context.prompter.interactive ? (mode.attempts ?? 3) : 1;
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const passphrase = await context.prompter.secret("Vault passphrase: ");
    try {
      return await Vault.unlock(dir, { passphrase });
    } catch (error) {
      if (!(error instanceof AuthError)) throw error;
      lastError = error;
      if (attempt < attempts) context.log?.("Wrong passphrase, try again.");
    }
  }
  throw lastError;
}

/** Fail-closed approval for step-up operations: any error means "no". */
export function makeApprover(context: Pick<AuthContext, "prompter" | "touchId">): (reason: string) => Promise<boolean> {
  return async (reason) => {
    try {
      if (context.touchId) return await context.touchId.confirm(reason);
      return await context.prompter.confirm(`Approve? ${reason}`);
    } catch {
      return false;
    }
  };
}
