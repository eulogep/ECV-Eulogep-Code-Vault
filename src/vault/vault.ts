import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, open as openFile, readFile, readdir, rename, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import {
  base32Decode,
  base32Encode,
  einsteinDerive,
  newScryptParams,
  open,
  randomKey,
  seal,
  stretchPassphrase,
  type ScryptParams,
} from "../crypto/einstein.js";
import { AuthError, EcvError, IntegrityError, NotFoundError } from "../errors.js";
import { presetPolicy, rosaireValidatePolicy, type Policy } from "../policy/plateau.js";
import { diataCanonicalPath } from "./paths.js";

const FORMAT_VERSION = 1;
const OBJECT_MAGIC = Buffer.from("ECV1");
const OBJECT_SALT_BYTES = 32;
const LOCK_TIMEOUT_MS = 10_000;
const LOCK_STALE_MS = 30_000;
const AUDIT_GENESIS = "0".repeat(64);

export interface PassphraseSlot {
  type: "passphrase";
  id: string;
  kdf: ScryptParams;
  wrapped: string;
}
export interface RecoverySlot {
  type: "recovery";
  id: string;
  wrapped: string;
}
/** Key wrapped by a secret held by a local authenticator (e.g. Touch ID via the macOS helper). */
export interface DeviceSlot {
  type: "device";
  id: string;
  account: string;
  wrapped: string;
}
export type KeySlot = PassphraseSlot | RecoverySlot | DeviceSlot;

export interface VaultHeader {
  format: "ecv";
  version: number;
  id: string;
  createdAt: string;
  slots: KeySlot[];
}

export interface FileEntry {
  object: string;
  size: number;
  mtimeMs: number;
  sha256: string;
}

export interface FileInfo {
  path: string;
  size: number;
  mtimeMs: number;
  sha256: string;
}

interface Manifest {
  version: number;
  seq: number;
  files: Map<string, FileEntry>;
  policy: Policy;
}

export type Credential =
  | { passphrase: string }
  | { recoveryCode: string }
  | { device: { account: string; secret: Uint8Array } };

export interface AuditEvent {
  actor: string;
  action: string;
  path?: string;
  decision: "allow" | "deny" | "step-up-approved" | "step-up-denied" | "error";
  detail?: string;
}

interface AuditRecord extends AuditEvent {
  seq: number;
  ts: string;
  prev: string;
}

export interface AuditReport {
  ok: boolean;
  entries: AuditRecord[];
  error?: string;
}

export interface CreateOptions {
  passphrase: string;
  kdf?: Partial<Pick<ScryptParams, "N" | "r" | "p">>;
}

function slotAad(vaultId: string, slotId: string): string {
  return `ecv/slot/v1|${vaultId}|${slotId}`;
}

function wrapKey(kek: Buffer, masterKey: Buffer, vaultId: string, slotId: string): string {
  return seal(kek, masterKey, slotAad(vaultId, slotId)).toString("base64");
}

function unwrapKey(kek: Buffer, slot: KeySlot, vaultId: string): Buffer {
  return open(kek, Buffer.from(slot.wrapped, "base64"), slotAad(vaultId, slot.id));
}

const deviceKek = (secret: Uint8Array): Buffer => einsteinDerive(secret, "ecv/kek/device/v1");
const recoveryKek = (code: string): Buffer => einsteinDerive(parseRecoveryCode(code), "ecv/kek/recovery/v1");
const passphraseKek = async (passphrase: string, kdf: ScryptParams): Promise<Buffer> =>
  einsteinDerive(await stretchPassphrase(passphrase, kdf), "ecv/kek/passphrase/v1");

function generateRecoveryCode(): string {
  return (base32Encode(randomBytes(20)).match(/.{4}/g) as string[]).join("-");
}

function parseRecoveryCode(code: string): Buffer {
  return base32Decode(code.replace(/[\s-]/g, "").toUpperCase());
}

async function atomicWrite(path: string, data: Uint8Array): Promise<void> {
  const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  const handle = await openFile(tmp, "w", 0o600);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(tmp, path);
}

async function withLock<T>(dir: string, fn: () => Promise<T>): Promise<T> {
  const lockPath = join(dir, ".lock");
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  for (;;) {
    try {
      const handle = await openFile(lockPath, "wx", 0o600);
      await handle.close();
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        const info = await stat(lockPath);
        if (Date.now() - info.mtimeMs > LOCK_STALE_MS) {
          await rm(lockPath, { force: true });
          continue;
        }
      } catch {
        continue;
      }
      if (Date.now() > deadline) throw new EcvError("LOCKED", "vault is busy, try again");
      await sleep(25);
    }
  }
  try {
    return await fn();
  } finally {
    await rm(lockPath, { force: true });
  }
}

const SLOT_TYPES = new Set(["passphrase", "recovery", "device"]);
const MAX_SCRYPT_MEMORY = 256 * 1024 * 1024;

const isBase64 = (value: unknown, minBytes: number): value is string =>
  typeof value === "string" && /^[A-Za-z0-9+/]+={0,2}$/.test(value) && Buffer.from(value, "base64").length >= minBytes;

/**
 * Parses and validates vault.json. The header is unauthenticated input: a hostile or
 * corrupted one must produce a clean error, and must not choose absurd KDF costs.
 */
function rosaireValidateHeader(raw: string): VaultHeader {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new IntegrityError("vault header is not valid JSON");
  }
  const header = parsed as Partial<VaultHeader> | null;
  if (
    typeof header !== "object" ||
    header === null ||
    header.format !== "ecv" ||
    header.version !== FORMAT_VERSION ||
    typeof header.id !== "string" ||
    typeof header.createdAt !== "string" ||
    !Array.isArray(header.slots) ||
    header.slots.length === 0 ||
    header.slots.length > 64
  ) {
    throw new IntegrityError("unsupported or corrupted vault header");
  }
  for (const slot of header.slots as unknown as Array<Record<string, unknown>>) {
    if (typeof slot !== "object" || slot === null || !SLOT_TYPES.has(slot.type as string) || typeof slot.id !== "string" || !isBase64(slot.wrapped, 28)) {
      throw new IntegrityError("corrupted key slot");
    }
    if (slot.type === "device" && typeof slot.account !== "string") throw new IntegrityError("corrupted key slot");
    if (slot.type === "passphrase") {
      const kdf = slot.kdf as Partial<ScryptParams> | undefined;
      const { N, r, p } = kdf ?? {};
      if (
        kdf?.alg !== "scrypt" ||
        typeof N !== "number" || typeof r !== "number" || typeof p !== "number" ||
        !Number.isInteger(N) || N < 1 << 10 || (N & (N - 1)) !== 0 ||
        !Number.isInteger(r) || r < 1 || r > 16 ||
        !Number.isInteger(p) || p < 1 || p > 16 ||
        128 * N * r > MAX_SCRYPT_MEMORY ||
        !isBase64(kdf.salt, 8)
      ) {
        throw new IntegrityError("key slot has unacceptable KDF parameters");
      }
    }
  }
  return header as VaultHeader;
}

const sha256Hex = (data: Uint8Array | string): string => createHash("sha256").update(data).digest("hex");

export class Vault {
  private readonly manifestKey: Buffer;
  private readonly auditKey: Buffer;
  private closed = false;

  private constructor(
    readonly dir: string,
    private header: VaultHeader,
    private readonly masterKey: Buffer,
  ) {
    this.manifestKey = einsteinDerive(masterKey, "ecv/manifest/v1");
    this.auditKey = einsteinDerive(masterKey, "ecv/audit/v1");
  }

  static async create(dir: string, options: CreateOptions): Promise<{ vault: Vault; recoveryCode: string }> {
    try {
      await stat(join(dir, "vault.json"));
      throw new EcvError("EXISTS", `a vault already exists in ${dir}`);
    } catch (error) {
      if (error instanceof EcvError) throw error;
    }
    await mkdir(join(dir, "objects"), { recursive: true, mode: 0o700 });

    const masterKey = randomKey();
    const id = randomUUID();
    const kdf = newScryptParams(options.kdf);
    const recoveryCode = generateRecoveryCode();
    const header: VaultHeader = {
      format: "ecv",
      version: FORMAT_VERSION,
      id,
      createdAt: new Date().toISOString(),
      slots: [
        {
          type: "passphrase",
          id: "passphrase-1",
          kdf,
          wrapped: wrapKey(await passphraseKek(options.passphrase, kdf), masterKey, id, "passphrase-1"),
        },
        {
          type: "recovery",
          id: "recovery-1",
          wrapped: wrapKey(recoveryKek(recoveryCode), masterKey, id, "recovery-1"),
        },
      ],
    };

    const vault = new Vault(dir, header, masterKey);
    await vault.writeManifest({ version: FORMAT_VERSION, seq: 0, files: new Map(), policy: presetPolicy("readonly") });
    await atomicWrite(join(dir, "vault.json"), Buffer.from(JSON.stringify(header, null, 2)));
    return { vault, recoveryCode };
  }

  static async readHeader(dir: string): Promise<VaultHeader> {
    let raw: string;
    try {
      raw = await readFile(join(dir, "vault.json"), "utf8");
    } catch {
      throw new NotFoundError(`no vault found in ${dir}`);
    }
    const header = rosaireValidateHeader(raw);
    return header;
  }

  static async unlock(dir: string, credential: Credential): Promise<Vault> {
    const header = await Vault.readHeader(dir);
    const attempts: Array<() => Promise<Buffer>> = [];

    if ("passphrase" in credential) {
      for (const slot of header.slots) {
        if (slot.type !== "passphrase") continue;
        attempts.push(async () => unwrapKey(await passphraseKek(credential.passphrase, slot.kdf), slot, header.id));
      }
    } else if ("recoveryCode" in credential) {
      for (const slot of header.slots) {
        if (slot.type !== "recovery") continue;
        attempts.push(async () => unwrapKey(recoveryKek(credential.recoveryCode), slot, header.id));
      }
    } else {
      for (const slot of header.slots) {
        if (slot.type !== "device" || slot.account !== credential.device.account) continue;
        attempts.push(async () => unwrapKey(deviceKek(credential.device.secret), slot, header.id));
      }
    }

    for (const attempt of attempts) {
      try {
        const masterKey = await attempt();
        const vault = new Vault(dir, header, masterKey);
        await vault.readManifest(); // proves the key is the right one and the manifest is intact
        return vault;
      } catch (error) {
        if (!(error instanceof IntegrityError)) throw error;
      }
    }
    throw new AuthError("authentication failed: wrong credential or corrupted vault");
  }

  close(): void {
    this.closed = true;
    this.masterKey.fill(0);
    this.manifestKey.fill(0);
    this.auditKey.fill(0);
  }

  get isClosed(): boolean {
    return this.closed;
  }

  get slots(): readonly KeySlot[] {
    return this.header.slots;
  }

  private assertOpen(): void {
    if (this.closed) throw new EcvError("CLOSED", "vault is closed");
  }

  private objectPath(objectId: string): string {
    return join(this.dir, "objects", `${objectId}.enc`);
  }

  private manifestAad(): string {
    return `ecv/manifest/v1|${this.header.id}`;
  }

  private async readManifest(): Promise<Manifest> {
    const blob = await readFile(join(this.dir, "manifest.enc")).catch((error: NodeJS.ErrnoException) => {
      throw error.code === "ENOENT" ? new IntegrityError("vault manifest is missing") : error;
    });
    const parsed = JSON.parse(open(this.manifestKey, blob, this.manifestAad()).toString("utf8")) as {
      version: number;
      seq: number;
      files: Array<[string, FileEntry]>;
      policy: unknown;
    };
    return {
      version: parsed.version,
      seq: parsed.seq,
      files: new Map(parsed.files),
      policy: rosaireValidatePolicy(parsed.policy),
    };
  }

  private async writeManifest(manifest: Manifest): Promise<void> {
    const json = JSON.stringify({ ...manifest, files: [...manifest.files.entries()] });
    await atomicWrite(join(this.dir, "manifest.enc"), seal(this.manifestKey, Buffer.from(json), this.manifestAad()));
  }

  private sealObject(objectId: string, plaintext: Uint8Array): Buffer {
    const salt = randomBytes(OBJECT_SALT_BYTES);
    const key = einsteinDerive(this.masterKey, `ecv/object/v1/${objectId}`, salt);
    try {
      return Buffer.concat([OBJECT_MAGIC, salt, seal(key, plaintext, `ecv/object/v1|${objectId}`)]);
    } finally {
      key.fill(0);
    }
  }

  private openObject(objectId: string, blob: Buffer): Buffer {
    const headerLength = OBJECT_MAGIC.length + OBJECT_SALT_BYTES;
    if (blob.length <= headerLength || !blob.subarray(0, OBJECT_MAGIC.length).equals(OBJECT_MAGIC)) {
      throw new IntegrityError("object has an invalid header");
    }
    const salt = blob.subarray(OBJECT_MAGIC.length, headerLength);
    const key = einsteinDerive(this.masterKey, `ecv/object/v1/${objectId}`, salt);
    try {
      return open(key, blob.subarray(headerLength), `ecv/object/v1|${objectId}`);
    } finally {
      key.fill(0);
    }
  }

  async list(): Promise<FileInfo[]> {
    this.assertOpen();
    const manifest = await this.readManifest();
    return [...manifest.files.entries()]
      .map(([path, entry]) => ({ path, size: entry.size, mtimeMs: entry.mtimeMs, sha256: entry.sha256 }))
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  async has(rawPath: string): Promise<boolean> {
    this.assertOpen();
    return (await this.readManifest()).files.has(diataCanonicalPath(rawPath));
  }

  async read(rawPath: string): Promise<Buffer> {
    this.assertOpen();
    const path = diataCanonicalPath(rawPath);
    const entry = (await this.readManifest()).files.get(path);
    if (!entry) throw new NotFoundError(`no such file in vault: ${path}`);
    const blob = await readFile(this.objectPath(entry.object)).catch((error: NodeJS.ErrnoException) => {
      throw error.code === "ENOENT" ? new IntegrityError(`data for ${path} is missing from the vault`) : error;
    });
    const plaintext = this.openObject(entry.object, blob);
    if (sha256Hex(plaintext) !== entry.sha256) {
      throw new IntegrityError(`content of ${path} does not match the manifest`);
    }
    return plaintext;
  }

  async write(rawPath: string, data: Uint8Array): Promise<void> {
    this.assertOpen();
    const path = diataCanonicalPath(rawPath);
    const objectId = randomBytes(16).toString("hex");
    const sealed = this.sealObject(objectId, data);
    const replaced = await withLock(this.dir, async () => {
      await atomicWrite(this.objectPath(objectId), sealed);
      const manifest = await this.readManifest();
      const previous = manifest.files.get(path)?.object;
      manifest.files.set(path, { object: objectId, size: data.length, mtimeMs: Date.now(), sha256: sha256Hex(data) });
      manifest.seq += 1;
      await this.writeManifest(manifest);
      return previous;
    });
    if (replaced) await rm(this.objectPath(replaced), { force: true });
  }

  async delete(rawPath: string): Promise<void> {
    this.assertOpen();
    const path = diataCanonicalPath(rawPath);
    const removed = await withLock(this.dir, async () => {
      const manifest = await this.readManifest();
      const entry = manifest.files.get(path);
      if (!entry) throw new NotFoundError(`no such file in vault: ${path}`);
      manifest.files.delete(path);
      manifest.seq += 1;
      await this.writeManifest(manifest);
      return entry.object;
    });
    await rm(this.objectPath(removed), { force: true });
  }

  async getPolicy(): Promise<Policy> {
    this.assertOpen();
    return (await this.readManifest()).policy;
  }

  async setPolicy(policy: Policy): Promise<void> {
    this.assertOpen();
    const valid = rosaireValidatePolicy(policy);
    await withLock(this.dir, async () => {
      const manifest = await this.readManifest();
      manifest.policy = valid;
      manifest.seq += 1;
      await this.writeManifest(manifest);
    });
  }

  /** Enrols a local authenticator secret as an additional way to unlock the vault. */
  async addDeviceSlot(account: string, secret: Uint8Array): Promise<void> {
    this.assertOpen();
    await withLock(this.dir, async () => {
      const header = await Vault.readHeader(this.dir);
      const id = `device-${randomBytes(4).toString("hex")}`;
      header.slots = header.slots.filter((slot) => !(slot.type === "device" && slot.account === account));
      header.slots.push({ type: "device", id, account, wrapped: wrapKey(deviceKek(secret), this.masterKey, header.id, id) });
      await atomicWrite(join(this.dir, "vault.json"), Buffer.from(JSON.stringify(header, null, 2)));
      this.header = header;
    });
  }

  async removeDeviceSlot(account: string): Promise<boolean> {
    this.assertOpen();
    return withLock(this.dir, async () => {
      const header = await Vault.readHeader(this.dir);
      const remaining = header.slots.filter((slot) => !(slot.type === "device" && slot.account === account));
      if (remaining.length === header.slots.length) return false;
      header.slots = remaining;
      await atomicWrite(join(this.dir, "vault.json"), Buffer.from(JSON.stringify(header, null, 2)));
      this.header = header;
      return true;
    });
  }

  /**
   * Replaces every passphrase slot with one for the new passphrase. This re-wraps the
   * same master key; it does not re-encrypt data, so it does not help against an
   * attacker who already holds a copy of the old vault and the old passphrase.
   */
  async changePassphrase(passphrase: string, kdf?: CreateOptions["kdf"]): Promise<void> {
    this.assertOpen();
    const params = newScryptParams(kdf);
    const kek = await passphraseKek(passphrase, params);
    await withLock(this.dir, async () => {
      const header = await Vault.readHeader(this.dir);
      const id = `passphrase-${randomBytes(4).toString("hex")}`;
      header.slots = [
        ...header.slots.filter((slot) => slot.type !== "passphrase"),
        { type: "passphrase", id, kdf: params, wrapped: wrapKey(kek, this.masterKey, header.id, id) },
      ];
      await atomicWrite(join(this.dir, "vault.json"), Buffer.from(JSON.stringify(header, null, 2)));
      this.header = header;
    });
  }

  /** Replaces the recovery slot with a fresh code, which is returned once. */
  async rotateRecoveryCode(): Promise<string> {
    this.assertOpen();
    const code = generateRecoveryCode();
    await withLock(this.dir, async () => {
      const header = await Vault.readHeader(this.dir);
      const id = `recovery-${randomBytes(4).toString("hex")}`;
      header.slots = [
        ...header.slots.filter((slot) => slot.type !== "recovery"),
        { type: "recovery", id, wrapped: wrapKey(recoveryKek(code), this.masterKey, header.id, id) },
      ];
      await atomicWrite(join(this.dir, "vault.json"), Buffer.from(JSON.stringify(header, null, 2)));
      this.header = header;
    });
    return code;
  }

  private auditAad(): string {
    return `ecv/audit/v1|${this.header.id}`;
  }

  private async readAuditLines(): Promise<string[]> {
    try {
      return (await readFile(join(this.dir, "audit.log"), "utf8")).split("\n").filter((line) => line.length > 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }

  /** Appends a hash-chained, encrypted audit record. */
  async audit(event: AuditEvent): Promise<void> {
    this.assertOpen();
    await withLock(this.dir, async () => {
      const lines = await this.readAuditLines();
      const last = lines.at(-1);
      const previous = last ? (JSON.parse(open(this.auditKey, Buffer.from(last, "base64"), this.auditAad()).toString("utf8")) as AuditRecord) : undefined;
      const record: AuditRecord = {
        seq: previous ? previous.seq + 1 : 0,
        ts: new Date().toISOString(),
        prev: last ? sha256Hex(last) : AUDIT_GENESIS,
        ...event,
      };
      const line = seal(this.auditKey, Buffer.from(JSON.stringify(record)), this.auditAad()).toString("base64");
      const handle = await openFile(join(this.dir, "audit.log"), "a", 0o600);
      try {
        await handle.appendFile(`${line}\n`);
        await handle.sync();
      } finally {
        await handle.close();
      }
    });
  }

  async verifyAudit(): Promise<AuditReport> {
    this.assertOpen();
    const entries: AuditRecord[] = [];
    let expectedPrev = AUDIT_GENESIS;
    for (const [index, line] of (await this.readAuditLines()).entries()) {
      try {
        const record = JSON.parse(open(this.auditKey, Buffer.from(line, "base64"), this.auditAad()).toString("utf8")) as AuditRecord;
        if (record.seq !== index || record.prev !== expectedPrev) {
          return { ok: false, entries, error: `chain broken at record ${index}` };
        }
        entries.push(record);
        expectedPrev = sha256Hex(line);
      } catch {
        return { ok: false, entries, error: `record ${index} failed authentication` };
      }
    }
    return { ok: true, entries };
  }

  /** Removes object files no longer referenced by the manifest (e.g. after a crash). */
  async collectGarbage(): Promise<number> {
    this.assertOpen();
    return withLock(this.dir, async () => {
      const referenced = new Set([...(await this.readManifest()).files.values()].map((entry) => `${entry.object}.enc`));
      let removed = 0;
      for (const name of await readdir(join(this.dir, "objects"))) {
        if (!referenced.has(name)) {
          await rm(join(this.dir, "objects", name), { force: true });
          removed += 1;
        }
      }
      return removed;
    });
  }
}
