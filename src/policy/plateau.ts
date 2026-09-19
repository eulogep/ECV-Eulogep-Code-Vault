import { PolicyError } from "../errors.js";

export const CAPABILITIES = ["list", "read", "search", "write", "delete"] as const;
export type Capability = (typeof CAPABILITIES)[number];

export interface PolicyRule {
  effect: "allow" | "deny";
  capabilities: Capability[];
  /** Glob patterns: `*` within a segment, `**` across segments, `?` one character. */
  paths: string[];
  /** Allowed only after an explicit, fresh human approval. */
  stepUp?: boolean;
}

export interface Policy {
  version: 1;
  preset?: string;
  sessionTtlSeconds: number;
  rules: PolicyRule[];
}

export type Decision =
  | { effect: "allow" }
  | { effect: "step-up" }
  | { effect: "deny"; reason: string };

const SECRET_PATHS = [
  "**/.env",
  "**/.env.*",
  "**/*.pem",
  "**/*.key",
  "**/id_rsa*",
  "**/id_ed25519*",
  "**/secrets/**",
];

const DEFAULT_TTL_SECONDS = 15 * 60;
export const MAX_GLOB_LENGTH = 512;

function denySecrets(): PolicyRule {
  return { effect: "deny", capabilities: [...CAPABILITIES], paths: [...SECRET_PATHS] };
}

/** Ready-made permission levels, from nothing to read/write. */
export const PLATEAU_PRESETS: Record<string, () => Policy> = {
  locked: () => ({ version: 1, preset: "locked", sessionTtlSeconds: DEFAULT_TTL_SECONDS, rules: [] }),
  readonly: () => ({
    version: 1,
    preset: "readonly",
    sessionTtlSeconds: DEFAULT_TTL_SECONDS,
    rules: [
      { effect: "allow", capabilities: ["list", "read", "search"], paths: ["**"] },
      denySecrets(),
    ],
  }),
  standard: () => ({
    version: 1,
    preset: "standard",
    sessionTtlSeconds: DEFAULT_TTL_SECONDS,
    rules: [
      { effect: "allow", capabilities: ["list", "read", "search", "write"], paths: ["**"] },
      { effect: "allow", capabilities: ["delete"], paths: ["**"], stepUp: true },
      denySecrets(),
    ],
  }),
};

export function presetPolicy(name: string): Policy {
  const factory = PLATEAU_PRESETS[name];
  if (!factory) {
    throw new PolicyError(`unknown preset '${name}' (available: ${Object.keys(PLATEAU_PRESETS).join(", ")})`);
  }
  return factory();
}

/** `*` and `?` inside one path segment, matched iteratively (no exponential backtracking). */
function segmentMatch(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    if (pattern[p] === "*") {
      star = p++;
      mark = t;
    } else if (p < pattern.length && (pattern[p] === "?" || pattern[p] === text[t])) {
      p++;
      t++;
    } else if (star >= 0) {
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (pattern[p] === "*") p++;
  return p === pattern.length;
}

/**
 * Matches a canonical path against a glob. A segment that is exactly `**` matches zero or
 * more whole segments; `*` and `?` never cross a `/`. Runs in O(glob segments x path
 * segments), so hostile paths or sloppy patterns cannot stall the gateway.
 */
export function globMatch(glob: string, path: string): boolean {
  const pattern = glob.split("/");
  const parts = path.split("/");
  const width = parts.length + 1;
  const memo = new Int8Array((pattern.length + 1) * width); // 0 unknown, 1 yes, 2 no
  const visit = (g: number, p: number): boolean => {
    const cached = memo[g * width + p];
    if (cached) return cached === 1;
    let result: boolean;
    if (g === pattern.length) result = p === parts.length;
    else if (pattern[g] === "**") result = visit(g + 1, p) || (p < parts.length && visit(g, p + 1));
    else result = p < parts.length && segmentMatch(pattern[g] as string, parts[p] as string) && visit(g + 1, p + 1);
    memo[g * width + p] = result ? 1 : 2;
    return result;
  };
  return visit(0, 0);
}

function matches(rule: PolicyRule, capability: Capability, path: string): boolean {
  return rule.capabilities.includes(capability) && rule.paths.some((glob) => globMatch(glob, path));
}

/**
 * Deny-overrides evaluation with default deny. `path` must already be canonical.
 * An allow that needs step-up only wins if no plain allow also matches.
 */
export function evaluatePolicy(policy: Policy, capability: Capability, path: string): Decision {
  let plainAllow = false;
  let stepUpAllow = false;
  for (const rule of policy.rules) {
    if (!matches(rule, capability, path)) continue;
    if (rule.effect === "deny") {
      return { effect: "deny", reason: `denied by policy rule for '${capability}' on '${path}'` };
    }
    if (rule.stepUp) stepUpAllow = true;
    else plainAllow = true;
  }
  if (plainAllow) return { effect: "allow" };
  if (stepUpAllow) return { effect: "step-up" };
  return { effect: "deny", reason: `'${capability}' on '${path}' is not granted by the current policy` };
}

/** Validates untrusted policy JSON (e.g. a file supplied to `ecv policy set`). */
export function rosaireValidatePolicy(input: unknown): Policy {
  if (typeof input !== "object" || input === null) throw new PolicyError("policy must be an object");
  const candidate = input as Record<string, unknown>;
  if (candidate.version !== 1) throw new PolicyError("policy.version must be 1");
  const ttl = candidate.sessionTtlSeconds;
  if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl < 30 || ttl > 24 * 3600) {
    throw new PolicyError("policy.sessionTtlSeconds must be an integer between 30 and 86400");
  }
  if (!Array.isArray(candidate.rules)) throw new PolicyError("policy.rules must be an array");
  const rules = candidate.rules.map((raw, index): PolicyRule => {
    const where = `policy.rules[${index}]`;
    if (typeof raw !== "object" || raw === null) throw new PolicyError(`${where} must be an object`);
    const rule = raw as Record<string, unknown>;
    if (rule.effect !== "allow" && rule.effect !== "deny") {
      throw new PolicyError(`${where}.effect must be 'allow' or 'deny'`);
    }
    if (!Array.isArray(rule.capabilities) || rule.capabilities.length === 0) {
      throw new PolicyError(`${where}.capabilities must be a non-empty array`);
    }
    const capabilities = rule.capabilities.map((cap) => {
      if (!CAPABILITIES.includes(cap as Capability)) throw new PolicyError(`${where}: unknown capability '${String(cap)}'`);
      return cap as Capability;
    });
    if (
      !Array.isArray(rule.paths) ||
      rule.paths.length === 0 ||
      rule.paths.some((p) => typeof p !== "string" || p === "" || p.length > MAX_GLOB_LENGTH)
    ) {
      throw new PolicyError(`${where}.paths must be a non-empty array of glob strings (max ${MAX_GLOB_LENGTH} characters)`);
    }
    if (rule.stepUp !== undefined && typeof rule.stepUp !== "boolean") {
      throw new PolicyError(`${where}.stepUp must be a boolean`);
    }
    if (rule.stepUp && rule.effect === "deny") {
      throw new PolicyError(`${where}: stepUp only applies to allow rules`);
    }
    return {
      effect: rule.effect,
      capabilities,
      paths: rule.paths as string[],
      ...(rule.stepUp ? { stepUp: true } : {}),
    };
  });
  return {
    version: 1,
    ...(typeof candidate.preset === "string" ? { preset: candidate.preset } : {}),
    sessionTtlSeconds: ttl,
    rules,
  };
}
