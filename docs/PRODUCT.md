# Product plan

## Positioning

> **`sudo` for AI coding agents.** Agents get exactly the files they need, for as long
> as you allow, with a human in the loop for anything destructive, and a log you can
> trust.

The encrypted vault is the mechanism; the *control point between an agent and your
code* is the product. Encrypting a folder is a commodity (git-crypt, age, SOPS). A
policy-enforcing, auditable gateway with hardware-backed approval for agents is not.

### Who pays

1. **Teams using coding agents on proprietary or regulated code** (finance, health,
   defence suppliers, agencies handling client IP) who need to show what an agent could
   and did access.
2. **Security-conscious individual developers and consultants** (free tier).
3. **Platform/security teams** who want a policy they define, not one each developer
   configures.

### Honest risks

- **Workflow friction.** Compilers and tests need plaintext. The wedge is *agent access*,
  not replacing your working tree; the vault is the source of truth and agents work
  through the gateway, with `checkout` as an explicit, audited escape hatch.
- **Agent vendors add sandboxes.** Built-in permission systems will improve. ECV
  differentiates by being agent-neutral (MCP), key-backed, and auditable off the
  vendor's infrastructure.
- **Security products live on trust.** Expect to need an independent audit before any
  enterprise sale.

## Open-core split

| Open source (Apache-2.0) | Commercial (Team / Enterprise) |
| --- | --- |
| Vault format, CLI, crypto | Shared vaults: per-user key slots, revocation, rotation |
| MCP gateway, policy engine, presets | Central policy management and org-wide baselines |
| Passphrase, recovery, Touch ID | Hardware keys (FIDO2/passkeys), Windows Hello, TPM |
| Local hash-chained audit log | Audit export (SIEM), off-machine anchoring, retention |
| | Remote approvals (phone push) for step-up |
| | SSO/SCIM, support, SLA, signed builds |

Keep the security-critical core fully open: people will not trust a closed vault.
Sell coordination, management and assurance.

## Roadmap

**0.1 (done).** Vault, key slots, policy, MCP gateway, sessions, audit,
Touch ID presence gate.

**0.2 — Hardening (in progress).**
- Done: `ecv passwd`, recovery-code rotation, `ecv seal`; format spec with
  cross-checked test vectors (`docs/FORMAT.md`); seeded fuzzing of the vault parser and
  policy validator; strict header validation; linear-time glob matching
- Secure Enclave–bound key with a Developer-ID-signed, notarised helper
- Real master-key rotation (re-encrypt all data), which `passwd` deliberately is not
- Git integration: vault-aware `git` remote helper, signed tags as rollback anchor
- Coverage-guided fuzzing and an external review of the format

**0.3 — Ergonomics.**
- Long-lived local daemon so several tools share one unlocked session
- Read-only FUSE/virtual filesystem view for tools that need real paths
- Redaction rules (return files with secrets masked instead of denying)
- Per-agent identities and per-agent policies

**0.4 — Teams.**
- Multi-user vaults with key slots per member, revocation with re-keying
- Approval over push notification; signed audit export

**1.0.** Independent security audit, stable format, Linux and Windows authenticators.

## Naming and provenance

Working name **ECV** / `ecv`. Check the npm, GitHub and trademark landscape before
public launch. Provenance rests on Git history, signed commits and releases, and the
LICENSE — sign the first commit and tag `v0.1.0`.
