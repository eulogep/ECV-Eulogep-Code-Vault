import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { PassThrough } from "node:stream";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { presetPolicy } from "../policy/plateau.js";
import { Vault } from "../vault/vault.js";
import { Gateway, serveStdio } from "./server.js";
import { NasaSession } from "./session.js";

const PASSPHRASE = "correct horse battery staple";
const FAST_KDF = { N: 1 << 10 };

let dir: string;
let approvals: string[];
let approveAnswer: boolean;
let unlocks: number;
let session: NasaSession;
let gateway: Gateway;
let nextId = 1;

async function call(name: string, args: Record<string, unknown> = {}) {
  const response = await gateway.handle({ jsonrpc: "2.0", id: nextId++, method: "tools/call", params: { name, arguments: args } });
  const result = (response as { result: { content: Array<{ text: string }>; isError?: boolean } }).result;
  return { text: result.content[0]?.text ?? "", isError: result.isError === true };
}

async function setup(preset: string, ttlSeconds?: number, now?: () => number): Promise<void> {
  const seed = (await Vault.create(dir, { passphrase: PASSPHRASE, kdf: FAST_KDF })).vault;
  await seed.write("src/app.ts", Buffer.from("export const answer = 42;\n// TODO refactor\n"));
  await seed.write("src/util.ts", Buffer.from("export const noop = () => {};\n"));
  await seed.write(".env", Buffer.from("API_KEY=hunter2"));
  await seed.write("blob.bin", Buffer.from([0xff, 0xfe, 0x00, 0x80]));
  await seed.setPolicy(presetPolicy(preset));
  seed.close();
  session = new NasaSession(
    async () => {
      unlocks += 1;
      return Vault.unlock(dir, { passphrase: PASSPHRASE });
    },
    ttlSeconds,
    now,
  );
  gateway = new Gateway({
    session,
    approve: async (reason) => {
      approvals.push(reason);
      return approveAnswer;
    },
  });
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "ecv-gw-"));
  approvals = [];
  approveAnswer = true;
  unlocks = 0;
});
afterEach(async () => {
  session?.expire();
  await rm(dir, { recursive: true, force: true });
});

describe("MCP protocol", () => {
  it("negotiates the protocol and lists tools", async () => {
    await setup("readonly");
    const init = (await gateway.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", clientInfo: { name: "test" } } })) as {
      result: { protocolVersion: string; serverInfo: { name: string } };
    };
    assert.equal(init.result.protocolVersion, "2025-06-18");
    assert.equal(init.result.serverInfo.name, "ecv-gateway");
    const tools = (await gateway.handle({ jsonrpc: "2.0", id: 2, method: "tools/list" })) as { result: { tools: Array<{ name: string }> } };
    assert.deepEqual(tools.result.tools.map((t) => t.name).sort(), ["vault_delete", "vault_list", "vault_read", "vault_search", "vault_status", "vault_write"]);
    assert.equal(unlocks, 0, "listing tools must not unlock the vault");
  });

  it("returns JSON-RPC errors for bad requests and ignores notifications", async () => {
    await setup("readonly");
    assert.equal((await gateway.handle({ jsonrpc: "2.0", method: "notifications/initialized" })), undefined);
    assert.equal(((await gateway.handle({ jsonrpc: "2.0", id: 1, method: "nope" })) as { error: { code: number } }).error.code, -32601);
    assert.equal(((await gateway.handle([])) as { error: { code: number } }).error.code, -32600);
    assert.equal(((await gateway.handle({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "rm_rf" } })) as { error: { code: number } }).error.code, -32602);
  });

  it("serves newline-delimited JSON over streams and survives garbage", async () => {
    await setup("readonly");
    const input = new PassThrough();
    const output = new PassThrough();
    let emitted = "";
    output.on("data", (chunk: Buffer) => {
      emitted += chunk.toString();
    });
    const done = serveStdio(gateway, input, output);
    input.write("not json\n");
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" })}\n`);
    input.end();
    await done;
    const lines = emitted.trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(lines[0].error.code, -32700);
    assert.deepEqual(lines[1], { jsonrpc: "2.0", id: 7, result: {} });
  });
});

describe("readonly policy", () => {
  beforeEach(() => setup("readonly"));

  it("lists only non-secret files and hides denied paths", async () => {
    const listing = await call("vault_list");
    assert.match(listing.text, /src\/app\.ts/);
    assert.ok(!listing.text.includes(".env"));
  });

  it("reads allowed files", async () => {
    assert.match((await call("vault_read", { path: "src/app.ts" })).text, /answer = 42/);
  });

  it("denies secrets identically whether or not they exist (no oracle)", async () => {
    const real = await call("vault_read", { path: ".env" });
    const missing = await call("vault_read", { path: "config/.env" });
    assert.equal(real.isError, true);
    assert.ok(!real.text.includes("hunter2"));
    assert.equal(missing.isError, true);
    assert.match(real.text, /denied by policy/);
    assert.match(missing.text, /denied by policy/);
  });

  it("denies writes and deletes without asking a human", async () => {
    assert.equal((await call("vault_write", { path: "src/new.ts", content: "x" })).isError, true);
    assert.equal((await call("vault_delete", { path: "src/util.ts" })).isError, true);
    assert.deepEqual(approvals, []);
  });

  it("blocks path traversal and bad arguments", async () => {
    assert.equal((await call("vault_read", { path: "../../etc/passwd" })).isError, true);
    assert.equal((await call("vault_read", { path: 42 })).isError, true);
    assert.equal((await call("vault_read", {})).isError, true);
  });

  it("reports binary files instead of dumping them", async () => {
    assert.match((await call("vault_read", { path: "blob.bin" })).text, /not valid UTF-8/);
  });

  it("searches without leaking denied files", async () => {
    assert.match((await call("vault_search", { query: "todo" })).text, /src\/app\.ts:2: \/\/ TODO refactor/);
    assert.equal((await call("vault_search", { query: "hunter2" })).text, "(no matches)");
  });

  it("audits allowed and denied calls, and the chain verifies", async () => {
    await call("vault_read", { path: "src/app.ts" });
    await call("vault_read", { path: ".env" });
    const vault = await Vault.unlock(dir, { passphrase: PASSPHRASE });
    const report = await vault.verifyAudit();
    vault.close();
    assert.equal(report.ok, true);
    assert.deepEqual(report.entries.map((e) => [e.action, e.decision, e.path]), [
      ["read", "allow", "src/app.ts"],
      ["read", "deny", ".env"],
    ]);
  });
});

describe("standard policy with step-up", () => {
  beforeEach(() => setup("standard"));

  it("writes without approval but asks a human before deleting", async () => {
    assert.equal((await call("vault_write", { path: "src/new.ts", content: "hi" })).isError, false);
    assert.deepEqual(approvals, []);

    approveAnswer = false;
    const refused = await call("vault_delete", { path: "src/util.ts" });
    assert.equal(refused.isError, true);
    assert.equal(approvals.length, 1);
    assert.match(String(approvals[0]),/'delete' on 'src\/util\.ts'/);
    assert.match((await call("vault_read", { path: "src/util.ts" })).text, /noop/);

    approveAnswer = true;
    assert.equal((await call("vault_delete", { path: "src/util.ts" })).isError, false);
    assert.equal((await call("vault_read", { path: "src/util.ts" })).isError, true);
  });

  it("still refuses to write secrets", async () => {
    assert.equal((await call("vault_write", { path: ".env", content: "x" })).isError, true);
  });
});

describe("session expiry", () => {
  it("re-authenticates after the TTL and zeroes the previous key", async () => {
    let clock = 1_000_000;
    await setup("readonly", 60, () => clock);
    await call("vault_status");
    assert.equal(unlocks, 1);
    await call("vault_list");
    assert.equal(unlocks, 1, "session is reused inside the TTL");

    const first = await session.acquire();
    clock += 61_000;
    await call("vault_list");
    assert.equal(unlocks, 2, "expired session must authenticate again");
    assert.equal(first.isClosed, true);
  });

  it("fails closed when re-authentication fails", async () => {
    await setup("readonly");
    session = new NasaSession(async () => {
      throw new Error("Touch ID refused");
    });
    gateway = new Gateway({ session, approve: async () => true });
    const result = await call("vault_read", { path: "src/app.ts" });
    assert.equal(result.isError, true);
    assert.match(result.text, /locked/);
  });
});
