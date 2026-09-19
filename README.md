# ECV — Eulogep Code Vault

**An encrypted source vault with policy-gated access for humans and AI agents.**

AI coding agents read and write your repository. Today that means handing them
the whole filesystem in plaintext. ECV keeps the code encrypted at rest and puts a
gateway in front of it: agents ask for specific files, a policy decides, risky
operations need your fingerprint, and everything is written to a tamper-evident
audit log.

```
 AI agent ──MCP──▶  ecv gateway  ──▶  policy ──▶  encrypted vault
                        │                │
                        │                └─ step-up: Touch ID before delete / export
                        └─ audit log (hash-chained, encrypted)
```

> **Status: v0.1 (alpha).** Working core, not yet independently audited. Read the
> [threat model](docs/THREAT_MODEL.md) before trusting it with anything valuable.

## What you get

- **Encrypted vault.** Every file is sealed with AES-256-GCM under its own derived
  key. File names, content and the file index are all encrypted; the policy lives
  *inside* the encrypted manifest so nobody can loosen it without the key.
- **Key slots.** The vault key is wrapped separately by your passphrase (scrypt), a
  one-time recovery code, and optionally Touch ID. Add or remove unlock methods
  without re-encrypting anything.
- **Agent gateway (MCP).** Six tools (`vault_list`, `vault_read`, `vault_search`,
  `vault_write`, `vault_delete`, `vault_status`) over stdio. Works with any MCP client.
- **Policy engine.** Deny-overrides, default-deny, glob-based (linear-time matching, so no regex stalls). Ships with `locked`,
  `readonly` and `standard` presets; secrets (`.env`, `*.pem`, `secrets/**`, …) are
  denied by default.
- **Step-up approval.** Rules can require a fresh Touch ID / terminal confirmation
  per call. If no human can be reached, the answer is *no*.
- **Time-boxed sessions.** The unlocked key lives in the gateway's memory only and is
  zeroed when the TTL expires.
- **Audit log.** Every allow, deny and approval is recorded in an encrypted,
  hash-chained log. `ecv audit --verify` detects edits and reordering.
- **Zero runtime dependencies.** Only Node's built-in crypto.

## Quick start

Requires Node ≥ 22. On macOS, Touch ID also needs the Swift toolchain (Xcode CLT).

```bash
npm install && npm run build
npm link                       # exposes the `ecv` command

cd my-project
ecv init                       # passphrase + one-time recovery code → ./.ecv
ecv import .                   # encrypt the tree (skips .git, node_modules)
ecv ls

# macOS: enable Touch ID
npm run build:native
ecv touchid enroll
```

### Give an agent controlled access

```bash
ecv policy set readonly        # or: standard, or your own JSON file
claude mcp add ecv -- ecv gateway --vault /path/to/my-project/.ecv
```

Any MCP client works; the server command is `ecv gateway --vault <dir>`. The first
tool call triggers the Touch ID prompt on *your* machine. Without a Touch ID slot the
passphrase is asked on your terminal, so run the client from a terminal.

### A custom policy

```json
{
  "version": 1,
  "sessionTtlSeconds": 900,
  "rules": [
    { "effect": "allow", "capabilities": ["list", "read", "search"], "paths": ["**"] },
    { "effect": "allow", "capabilities": ["write"], "paths": ["src/**", "tests/**"] },
    { "effect": "allow", "capabilities": ["delete"], "paths": ["src/**"], "stepUp": true },
    { "effect": "deny",  "capabilities": ["list", "read", "search", "write", "delete"],
      "paths": ["**/.env*", "**/*.pem", "secrets/**"] }
  ]
}
```

```bash
ecv policy set ./policy.json
```

Capabilities: `list`, `read`, `search`, `write`, `delete`. A `deny` always wins; an
`allow` with `stepUp` needs a human approval each time; anything unmatched is denied.

## Commands

| Command | What it does |
| --- | --- |
| `ecv init [--touchid]` | Create a vault |
| `ecv import <dir>` | Encrypt a directory into the vault (only changed files are rewritten) |
| `ecv seal <dir> [--prune]` | Sync a working copy back; `--prune` also removes files deleted from it |
| `ecv ls`, `cat`, `put`, `rm` | Work with files in the vault |
| `ecv checkout <dir>` | Decrypt everything into a directory (plaintext on disk) |
| `ecv policy show` / `set` | Inspect or change what agents may do |
| `ecv gateway [--ttl s]` | Serve the vault to agents over MCP |
| `ecv audit [--verify]` | Show and verify the audit log |
| `ecv touchid enroll` / `remove` | Manage Touch ID |
| `ecv passwd` | Change the passphrase |
| `ecv recovery rotate` | Issue a new recovery code |
| `ecv status` | Show vault info without unlocking |

Set `--vault <dir>` or `ECV_VAULT`; the default is `./.ecv`.
`ECV_PASSPHRASE` supplies the passphrase non-interactively (CI only).

## Development

```bash
npm test        # build + 57 tests: crypto vectors, tampering, fuzzing, policy, MCP protocol, sessions
npm run typecheck
```

Layout: `src/crypto` primitives · `src/vault` storage format · `src/policy` rules ·
`src/auth` Touch ID / prompts · `src/gateway` MCP server and sessions ·
`native/macos` Swift helper.

## Documentation

- [Threat model and limits](docs/THREAT_MODEL.md) — what ECV does and does not protect
- [Vault format](docs/FORMAT.md) — on-disk specification with known-answer test vectors
- [Product plan](docs/PRODUCT.md) — roadmap and open-core model

## License

Apache-2.0. See [LICENSE](LICENSE).
