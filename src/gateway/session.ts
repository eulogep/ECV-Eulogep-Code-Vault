import type { Vault } from "../vault/vault.js";

/**
 * A time-boxed unlocked session. The master key lives only in this process's
 * memory; when the TTL runs out the vault is closed and the key zeroed, and the
 * next access must authenticate again.
 */
export class NasaSession {
  private vault: Vault | null = null;
  private expiresAt = 0;
  private timer: NodeJS.Timeout | undefined;
  private pending: Promise<Vault> | null = null;

  constructor(
    private readonly authenticate: () => Promise<Vault>,
    private readonly ttlOverrideSeconds?: number,
    private readonly now: () => number = Date.now,
  ) {}

  get remainingSeconds(): number {
    return this.vault ? Math.max(0, Math.ceil((this.expiresAt - this.now()) / 1000)) : 0;
  }

  async acquire(): Promise<Vault> {
    if (this.vault && !this.vault.isClosed && this.now() < this.expiresAt) return this.vault;
    this.expire();
    this.pending ??= this.begin().finally(() => {
      this.pending = null;
    });
    return this.pending;
  }

  private async begin(): Promise<Vault> {
    const vault = await this.authenticate();
    const ttl = this.ttlOverrideSeconds ?? (await vault.getPolicy()).sessionTtlSeconds;
    this.vault = vault;
    this.expiresAt = this.now() + ttl * 1000;
    this.timer = setTimeout(() => this.expire(), ttl * 1000);
    this.timer.unref();
    return vault;
  }

  expire(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    this.vault?.close();
    this.vault = null;
    this.expiresAt = 0;
  }
}
