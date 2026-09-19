import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { PolicyError } from "../errors.js";
import { evaluatePolicy, globMatch, presetPolicy, rosaireValidatePolicy } from "./plateau.js";

describe("globMatch", () => {
  it("handles *, ** and ?", () => {
    assert.ok(globMatch("src/*.ts", "src/a.ts"));
    assert.ok(!globMatch("src/*.ts", "src/x/a.ts"));
    assert.ok(globMatch("src/**", "src/x/y/a.ts"));
    assert.ok(globMatch("**", "a.ts"));
    assert.ok(globMatch("**/.env", ".env"));
    assert.ok(globMatch("**/.env", "a/b/.env"));
    assert.ok(!globMatch("**/.env", "a/b/.env.local"));
    assert.ok(globMatch("**/.env.*", "config/.env.production"));
    assert.ok(globMatch("**/id_rsa*", "home/.ssh/id_rsa.pub"));
    assert.ok(globMatch("a?c", "abc"));
    assert.ok(!globMatch("a?c", "a/c"));
    assert.ok(globMatch("a/**/z", "a/z"));
    assert.ok(globMatch("a/**/z", "a/b/c/z"));
    assert.ok(!globMatch("a/**/z", "a/b/c"));
  });
  it("treats a trailing /** as also covering a file named like the directory (safe for deny rules)", () => {
    assert.ok(globMatch("secrets/**", "secrets"));
  });
  it("matches metacharacters literally", () => {
    assert.ok(!globMatch("a.b", "axb"));
    assert.ok(globMatch("a+b(c)", "a+b(c)"));
  });
  it("handles multiple wildcards within a segment", () => {
    assert.ok(globMatch("*a*b*", "xxaxxbxx"));
    assert.ok(!globMatch("*a*b*", "xxbxxaxx"));
    assert.ok(globMatch("a**b", "axxb"));
  });
});

describe("evaluatePolicy", () => {
  it("denies everything when locked", () => {
    assert.equal(evaluatePolicy(presetPolicy("locked"), "read", "a.ts").effect, "deny");
  });
  it("readonly allows reads but not writes", () => {
    const policy = presetPolicy("readonly");
    assert.equal(evaluatePolicy(policy, "read", "src/a.ts").effect, "allow");
    assert.equal(evaluatePolicy(policy, "write", "src/a.ts").effect, "deny");
  });
  it("standard requires step-up for delete", () => {
    assert.equal(evaluatePolicy(presetPolicy("standard"), "delete", "src/a.ts").effect, "step-up");
    assert.equal(evaluatePolicy(presetPolicy("standard"), "write", "src/a.ts").effect, "allow");
  });
  it("secret paths are denied for every capability, even when a broader allow matches", () => {
    const policy = presetPolicy("standard");
    for (const path of [".env", "config/.env.production", "certs/server.pem", "keys/deploy.key", "secrets/x.json", "home/.ssh/id_ed25519"]) {
      for (const cap of ["list", "read", "search", "write", "delete"] as const) {
        assert.equal(evaluatePolicy(policy, cap, path).effect, "deny", `${cap} ${path}`);
      }
    }
  });
  it("a plain allow beats a step-up allow", () => {
    const policy = rosaireValidatePolicy({
      version: 1,
      sessionTtlSeconds: 60,
      rules: [
        { effect: "allow", capabilities: ["write"], paths: ["**"], stepUp: true },
        { effect: "allow", capabilities: ["write"], paths: ["docs/**"] },
      ],
    });
    assert.equal(evaluatePolicy(policy, "write", "docs/a.md").effect, "allow");
    assert.equal(evaluatePolicy(policy, "write", "src/a.ts").effect, "step-up");
  });
});

describe("rosaireValidatePolicy", () => {
  const valid = { version: 1, sessionTtlSeconds: 600, rules: [{ effect: "allow", capabilities: ["read"], paths: ["**"] }] };
  it("accepts a valid policy", () => {
    assert.equal(rosaireValidatePolicy(valid).rules.length, 1);
  });
  it("rejects malformed input", () => {
    const bad: unknown[] = [
      null,
      { ...valid, version: 2 },
      { ...valid, sessionTtlSeconds: 1 },
      { ...valid, sessionTtlSeconds: 1e9 },
      { ...valid, rules: "x" },
      { ...valid, rules: [{ effect: "maybe", capabilities: ["read"], paths: ["**"] }] },
      { ...valid, rules: [{ effect: "allow", capabilities: ["fly"], paths: ["**"] }] },
      { ...valid, rules: [{ effect: "allow", capabilities: [], paths: ["**"] }] },
      { ...valid, rules: [{ effect: "allow", capabilities: ["read"], paths: [""] }] },
      { ...valid, rules: [{ effect: "allow", capabilities: ["read"], paths: ["a".repeat(513)] }] },
      { ...valid, rules: [{ effect: "deny", capabilities: ["read"], paths: ["**"], stepUp: true }] },
    ];
    for (const input of bad) assert.throws(() => rosaireValidatePolicy(input), PolicyError, JSON.stringify(input));
  });
});
