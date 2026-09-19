import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { AuthError, IntegrityError, NotFoundError, PathError } from "../errors.js";
import { open, seal, randomKey } from "../crypto/einstein.js";
import { diataCanonicalPath } from "./paths.js";
import { Vault } from "./vault.js";

const FAST_KDF = { N: 1 << 10 };
const PASSPHRASE = "correct horse battery staple";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "ecv-test-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("crypto primitives", () => {
  it("round-trips and rejects tampering, wrong key and wrong AAD", () => {
    const key = randomKey();
    const blob = seal(key, Buffer.from("secret"), "aad");
    assert.equal(open(key, blob, "aad").toString(), "secret");
    assert.throws(() => open(randomKey(), blob, "aad"), IntegrityError);
    assert.throws(() => open(key, blob, "other-aad"), IntegrityError);
    const flipped = Buffer.from(blob);
    flipped[15] = (flipped[15] as number) ^ 1;
    assert.throws(() => open(key, flipped, "aad"), IntegrityError);
    assert.throws(() => open(key, blob.subarray(0, 10), "aad"), IntegrityError);
  });
});

describe("diataCanonicalPath", () => {
  it("normalises separators and dot segments", () => {
    assert.equal(diataCanonicalPath("./src//app\\main.ts"), "src/app/main.ts");
  });
  it("rejects traversal, absolute paths and control characters", () => {
    for (const bad of ["../x", "a/../../x", "/etc/passwd", "C:\\x", "a\0b", "", ".", "a/.."]) {
      assert.throws(() => diataCanonicalPath(bad), PathError, JSON.stringify(bad));
    }
    assert.throws(() => diataCanonicalPath(42), PathError);
  });
});

describe("Vault", () => {
  it("stores files encrypted: neither content nor names appear on disk", async () => {
    const { vault } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    await vault.write("src/very-secret-name.ts", Buffer.from("const apiToken = 'PLAINTEXT-MARKER';"));
    vault.close();

    const walk = async (base: string): Promise<string[]> =>
      (await readdir(base, { withFileTypes: true })).flatMap((e) => (e.isDirectory() ? [] : [join(base, e.name)]));
    const files = [...(await walk(dir)), ...(await walk(join(dir, "objects")))];
    for (const file of files) {
      const raw = (await readFile(file)).toString("latin1");
      assert.ok(!raw.includes("PLAINTEXT-MARKER"), `${file} leaks content`);
      assert.ok(!raw.includes("very-secret-name"), `${file} leaks file names`);
    }
  });

  it("round-trips files across an unlock with the passphrase", async () => {
    const created = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    await created.vault.write("a/b.txt", Buffer.from("hello"));
    created.vault.close();

    const vault = await Vault.unlock(dir, { passphrase: PASSPHRASE });
    assert.equal((await vault.read("a/b.txt")).toString(), "hello");
    assert.deepEqual((await vault.list()).map((f) => f.path), ["a/b.txt"]);
    vault.close();
  });

  it("rejects a wrong passphrase", async () => {
    (await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF })).vault.close();
    await assert.rejects(Vault.unlock(dir, { passphrase: "wrong wrong wrong" }), AuthError);
  });

  it("unlocks with the recovery code, with or without dashes and case", async () => {
    const { vault, recoveryCode } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    await vault.write("x", Buffer.from("1"));
    vault.close();
    const again = await Vault.unlock(dir, { recoveryCode: recoveryCode.toLowerCase().replaceAll("-", " ") });
    assert.equal((await again.read("x")).toString(), "1");
    again.close();
    await assert.rejects(Vault.unlock(dir, { recoveryCode: "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA" }), AuthError);
  });

  it("detects a tampered object", async () => {
    const { vault } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    await vault.write("f", Buffer.from("payload"));
    const [name] = await readdir(join(dir, "objects"));
    const path = join(dir, "objects", name as string);
    const blob = await readFile(path);
    blob[blob.length - 1] = (blob[blob.length - 1] as number) ^ 1;
    await writeFile(path, blob);
    await assert.rejects(vault.read("f"), IntegrityError);
    vault.close();
  });

  it("detects an object swapped with another valid object", async () => {
    const { vault } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    await vault.write("a", Buffer.from("AAAA"));
    await vault.write("b", Buffer.from("BBBB"));
    const [first, second] = await readdir(join(dir, "objects"));
    const a = await readFile(join(dir, "objects", first as string));
    await writeFile(join(dir, "objects", second as string), a);
    await assert.rejects(Promise.all([vault.read("a"), vault.read("b")]), IntegrityError);
    vault.close();
  });

  it("detects a tampered manifest at unlock", async () => {
    (await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF })).vault.close();
    const manifest = await readFile(join(dir, "manifest.enc"));
    manifest[20] = (manifest[20] as number) ^ 1;
    await writeFile(join(dir, "manifest.enc"), manifest);
    await assert.rejects(Vault.unlock(dir, { passphrase: PASSPHRASE }), AuthError);
  });

  it("overwrites and deletes, removing stale objects", async () => {
    const { vault } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    await vault.write("f", Buffer.from("v1"));
    await vault.write("f", Buffer.from("v2"));
    assert.equal((await vault.read("f")).toString(), "v2");
    assert.equal((await readdir(join(dir, "objects"))).length, 1);
    await vault.delete("f");
    assert.equal((await readdir(join(dir, "objects"))).length, 0);
    await assert.rejects(vault.read("f"), NotFoundError);
    vault.close();
  });

  it("handles the __proto__ path without prototype pollution", async () => {
    const { vault } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    await vault.write("__proto__", Buffer.from("x"));
    assert.deepEqual((await vault.list()).map((f) => f.path), ["__proto__"]);
    assert.equal(({} as Record<string, unknown>).size, undefined);
    vault.close();
  });

  it("serialises concurrent writers without losing files", async () => {
    const { vault } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    await Promise.all(Array.from({ length: 20 }, (_, i) => vault.write(`f${i}`, Buffer.from(String(i)))));
    assert.equal((await vault.list()).length, 20);
    vault.close();
  });

  it("zeroes the key and refuses use after close", async () => {
    const { vault } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    vault.close();
    await assert.rejects(vault.list(), /closed/);
  });

  it("supports device slots and refuses the wrong device secret", async () => {
    const { vault } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    const secret = randomKey();
    await vault.addDeviceSlot("default", secret);
    vault.close();
    (await Vault.unlock(dir, { device: { account: "default", secret } })).close();
    await assert.rejects(Vault.unlock(dir, { device: { account: "default", secret: randomKey() } }), AuthError);
    const again = await Vault.unlock(dir, { passphrase: PASSPHRASE });
    assert.equal(await again.removeDeviceSlot("default"), true);
    again.close();
    await assert.rejects(Vault.unlock(dir, { device: { account: "default", secret } }), AuthError);
  });

  it("keeps a verifiable audit chain and detects edits and reordering", async () => {
    const { vault } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF });
    for (const action of ["read", "write", "delete"]) await vault.audit({ actor: "t", action, decision: "allow" });
    assert.deepEqual(
      (await vault.verifyAudit()).entries.map((e) => e.action),
      ["read", "write", "delete"],
    );
    assert.equal((await vault.verifyAudit()).ok, true);

    const path = join(dir, "audit.log");
    const lines = (await readFile(path, "utf8")).trim().split("\n");
    await writeFile(path, `${[lines[1], lines[0], lines[2]].join("\n")}\n`);
    assert.equal((await vault.verifyAudit()).ok, false);

    await writeFile(path, `${[lines[0], lines[2]].join("\n")}\n`); // deleted the middle record
    assert.equal((await vault.verifyAudit()).ok, false);
    vault.close();
  });
});
