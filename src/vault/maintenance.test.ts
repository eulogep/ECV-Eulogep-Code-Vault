import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { AuthError, EcvError, IntegrityError } from "../errors.js";
import { syncDirectory } from "./sync.js";
import { Vault } from "./vault.js";

const FAST_KDF = { N: 1 << 10 };
const OLD = "correct horse battery staple";
const NEW = "another long passphrase 42";

let root: string;
let vaultDir: string;
let work: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "ecv-maint-"));
  vaultDir = join(root, "vault");
  work = join(root, "work");
  await mkdir(join(work, "src"), { recursive: true });
});
afterEach(() => rm(root, { recursive: true, force: true }));

describe("credential maintenance", () => {
  it("changes the passphrase: new works, old and stale slots do not", async () => {
    const { vault } = await Vault.create(vaultDir, { passphrase: OLD, kdf: FAST_KDF });
    await vault.write("f", Buffer.from("data"));
    await vault.changePassphrase(NEW, FAST_KDF);
    vault.close();

    await assert.rejects(Vault.unlock(vaultDir, { passphrase: OLD }), AuthError);
    const again = await Vault.unlock(vaultDir, { passphrase: NEW });
    assert.equal((await again.read("f")).toString(), "data");
    assert.equal(again.slots.filter((slot) => slot.type === "passphrase").length, 1);
    again.close();
  });

  it("keeps the recovery code working across a passphrase change", async () => {
    const { vault, recoveryCode } = await Vault.create(vaultDir, { passphrase: OLD, kdf: FAST_KDF });
    await vault.changePassphrase(NEW, FAST_KDF);
    vault.close();
    (await Vault.unlock(vaultDir, { recoveryCode })).close();
  });

  it("rotates the recovery code: the old one stops working", async () => {
    const { vault, recoveryCode: oldCode } = await Vault.create(vaultDir, { passphrase: OLD, kdf: FAST_KDF });
    const newCode = await vault.rotateRecoveryCode();
    vault.close();
    assert.notEqual(newCode, oldCode);
    await assert.rejects(Vault.unlock(vaultDir, { recoveryCode: oldCode }), AuthError);
    (await Vault.unlock(vaultDir, { recoveryCode: newCode })).close();
  });
});

describe("hostile headers", () => {
  it("rejects absurd KDF parameters instead of exhausting memory", async () => {
    (await Vault.create(vaultDir, { passphrase: OLD, kdf: FAST_KDF })).vault.close();
    const path = join(vaultDir, "vault.json");
    const header = JSON.parse(await readFile(path, "utf8"));
    header.slots[0].kdf.N = 2 ** 30;
    await writeFile(path, JSON.stringify(header));
    await assert.rejects(Vault.unlock(vaultDir, { passphrase: OLD }), IntegrityError);
  });

  it("rejects a header that is not JSON", async () => {
    (await Vault.create(vaultDir, { passphrase: OLD, kdf: FAST_KDF })).vault.close();
    await writeFile(join(vaultDir, "vault.json"), "{ nope");
    await assert.rejects(Vault.unlock(vaultDir, { passphrase: OLD }), IntegrityError);
  });
});

describe("syncDirectory", () => {
  it("adds, updates, skips unchanged, and prunes deleted files", async () => {
    const { vault } = await Vault.create(vaultDir, { passphrase: OLD, kdf: FAST_KDF });
    await writeFile(join(work, "a.txt"), "A");
    await writeFile(join(work, "src", "b.txt"), "B");
    await mkdir(join(work, "node_modules"));
    await writeFile(join(work, "node_modules", "skip.js"), "x");

    assert.deepEqual(await syncDirectory(vault, work), { added: 2, updated: 0, unchanged: 0, removed: 0, skipped: [] });
    assert.deepEqual(await syncDirectory(vault, work), { added: 0, updated: 0, unchanged: 2, removed: 0, skipped: [] });

    await writeFile(join(work, "a.txt"), "A2");
    await rm(join(work, "src", "b.txt"));
    assert.deepEqual(await syncDirectory(vault, work), { added: 0, updated: 1, unchanged: 0, removed: 0, skipped: [] });
    assert.deepEqual(await syncDirectory(vault, work, { prune: true }), { added: 0, updated: 0, unchanged: 1, removed: 1, skipped: [] });
    assert.deepEqual((await vault.list()).map((f) => f.path), ["a.txt"]);
    vault.close();
  });

  it("prunes only under the prefix", async () => {
    const { vault } = await Vault.create(vaultDir, { passphrase: OLD, kdf: FAST_KDF });
    await vault.write("other/keep.txt", Buffer.from("k"));
    await writeFile(join(work, "a.txt"), "A");
    await syncDirectory(vault, work, { prefix: "app", prune: true });
    assert.deepEqual((await vault.list()).map((f) => f.path), ["app/a.txt", "other/keep.txt"]);
    vault.close();
  });

  it("refuses to prune against an empty directory unless forced", async () => {
    const { vault } = await Vault.create(vaultDir, { passphrase: OLD, kdf: FAST_KDF });
    await vault.write("precious.txt", Buffer.from("p"));
    const empty = join(root, "empty");
    await mkdir(empty);
    await assert.rejects(syncDirectory(vault, empty, { prune: true }), EcvError);
    assert.equal((await vault.list()).length, 1);
    assert.equal((await syncDirectory(vault, empty, { prune: true, force: true })).removed, 1);
    vault.close();
  });
});
