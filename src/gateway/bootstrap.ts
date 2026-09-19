import { makeApprover, rosaireUnlock, type AuthContext } from "../auth/rosaire.js";
import { Gateway, serveStdio } from "./server.js";
import { NasaSession } from "./session.js";

export interface BootstrapOptions {
  vaultDir: string;
  auth: AuthContext;
  ttlSeconds?: number;
}

/**
 * Starts the MCP gateway on stdio. Authentication is lazy: the first tool call
 * triggers the Touch ID / passphrase prompt on the human's terminal, and again
 * whenever the session TTL has elapsed.
 */
export async function nasaBootstrap(options: BootstrapOptions): Promise<void> {
  const session = new NasaSession(
    () => rosaireUnlock(options.vaultDir, options.auth, { attempts: 1 }),
    options.ttlSeconds,
  );
  const gateway = new Gateway({ session, approve: makeApprover(options.auth) });

  const shutdown = (): void => {
    session.expire();
    process.exit(0);
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);

  try {
    await serveStdio(gateway, process.stdin, process.stdout);
  } finally {
    session.expire();
  }
}
