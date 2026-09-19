import assert from "node:assert/strict";
import { readFile, readdir, rm, writeFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { EcvError } from "./errors.js";
import { globMatch, rosaireValidatePolicy } from "./policy/plateau.js";
import { Vault } from "./vault/vault.js";

// Deterministic PRNG (mulberry32) so failures are reproducible.
function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const PASSPHRASE = "correct horse battery staple";
const CONTENT: Record<string, string> = { "a.txt": "alpha", "dir/b.txt": "bravo", "dir/c.txt": "charlie" };

describe("fuzzing a vault on disk", () => {
  it("never yields wrong plaintext or an unexpected exception after random corruption", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ecv-fuzz-"));
    try {
      const { vault } = await Vault.create(dir, { passphrase: PASSPHRASE, kdf: { N: 1 << 10 } });
      for (const [path, text] of Object.entries(CONTENT)) await vault.write(path, Buffer.from(text));
      await vault.audit({ actor: "fuzz", action: "read", decision: "allow" });
      vault.close();

      const targets = ["vault.json", "manifest.enc", "audit.log", ...(await readdir(join(dir, "objects"))).map((n) => `objects/${n}`)];
      const originals = new Map<string, Buffer>();
      for (const target of targets) originals.set(target, await readFile(join(dir, target)));

      const random = prng(0xec5f);
      let rejected = 0;
      let survived = 0;
      for (let round = 0; round < 300; round++) {
        const target = targets[Math.floor(random() * targets.length)] as string;
        const original = originals.get(target) as Buffer;
        let mutated = Buffer.from(original);
        switch (Math.floor(random() * 4)) {
          case 0: {
            const index = Math.floor(random() * mutated.length);
            mutated[index] = (mutated[index] ?? 0) ^ (1 << Math.floor(random() * 8));
            break;
          }
          case 1:
            mutated = mutated.subarray(0, Math.floor(random() * mutated.length));
            break;
          case 2:
            mutated = Buffer.concat([mutated, Buffer.from([Math.floor(random() * 256)])]);
            break;
          default:
            for (let i = 0; i < 8; i++) mutated[Math.floor(random() * mutated.length)] = Math.floor(random() * 256);
        }
        await writeFile(join(dir, target), mutated);

        try {
          const vault = await Vault.unlock(dir, { passphrase: PASSPHRASE });
          try {
            for (const [path, text] of Object.entries(CONTENT)) {
              try {
                assert.equal((await vault.read(path)).toString(), text, `${target}: wrong plaintext for ${path}`);
              } catch (error) {
                if (!(error instanceof EcvError)) throw error;
              }
            }
            await vault.verifyAudit();
            survived += 1;
          } finally {
            vault.close();
          }
        } catch (error) {
          if (!(error instanceof EcvError)) throw new Error(`unexpected ${(error as Error).name} after mutating ${target}: ${(error as Error).message}`);
          rejected += 1;
        }
        await writeFile(join(dir, target), original);
      }
      assert.ok(rejected > 0 && survived > 0, `expected a mix of outcomes, got rejected=${rejected} survived=${survived}`);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("fuzzing the policy engine", () => {
  it("rosaireValidatePolicy only ever accepts or throws EcvError", () => {
    const random = prng(7);
    const atoms: unknown[] = [null, undefined, 0, -1, 1e12, "", "**", "allow", "deny", "read", true, [], {}, [1], ["**"], { effect: "allow" }];
    const pick = (): unknown => atoms[Math.floor(random() * atoms.length)];
    for (let i = 0; i < 2000; i++) {
      const candidate = {
        version: random() < 0.7 ? 1 : pick(),
        sessionTtlSeconds: random() < 0.7 ? 600 : pick(),
        rules: random() < 0.8 ? [{ effect: pick(), capabilities: random() < 0.5 ? ["read"] : pick(), paths: random() < 0.5 ? ["**"] : pick(), stepUp: pick() }] : pick(),
      };
      try {
        rosaireValidatePolicy(candidate);
      } catch (error) {
        assert.ok(error instanceof EcvError, `non-EcvError for ${JSON.stringify(candidate)}: ${String(error)}`);
      }
    }
  });

  it("glob matching stays fast on pathological patterns", () => {
    const longPath = `${"a/".repeat(500)}b`;
    for (const glob of [`${"**/".repeat(12)}x`, `${"*/".repeat(20)}x`, "**/**/**/**/**/**/**/**/x", `${"**".repeat(30)}x`, `${"*a".repeat(30)}x`, `${"**a".repeat(30)}x`, `${"**/a/".repeat(40)}x`]) {
      const started = performance.now();
      globMatch(glob, longPath);
      assert.ok(performance.now() - started < 200, `${glob} took ${performance.now() - started}ms`);
    }
  });
});
