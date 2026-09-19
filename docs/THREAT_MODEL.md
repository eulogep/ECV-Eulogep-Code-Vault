# Threat model

ECV reduces what an AI agent (or malware, or a stolen disk) can do with your source
code. It is not magic: code that has been decrypted can be copied. This page states
plainly what is and is not protected.

## Assets

1. Source code confidentiality and integrity.
2. The vault master key (32 random bytes).
3. The policy that limits agents.
4. The audit trail.

## Design in one paragraph

A random master key encrypts everything. It is stored only *wrapped* in key slots
(passphrase via scrypt N=2^17, recovery code, optional device secret). Each file is
encrypted with AES-256-GCM under a key derived by HKDF from the master key, a
per-write random salt and the object id, with the object id bound as authenticated
data. File names, sizes, hashes and the policy live in an encrypted manifest.
Agents never touch the vault files: they talk to the gateway, which evaluates the
policy on every call.

## What ECV protects against

| Threat | Outcome |
| --- | --- |
| Someone (or an agent) reads the vault directory while it is locked | Only random-looking bytes and a file count. Names and content are encrypted. |
| Ciphertext is modified, or one object is swapped for another valid one | Detected on read (AEAD + manifest hash binding). |
| The manifest or key slots are edited | Unlock fails; forged slots cannot wrap the master key. |
| An agent asks for a secret or a path outside its grant | Denied. Denied paths give the same answer whether or not they exist. |
| An agent uses `../` or absolute paths | Rejected by path canonicalisation before any policy or storage call. |
| An agent tries to raise its own permissions | The gateway exposes no policy tool; the policy is inside the encrypted manifest. |
| An agent deletes or exports on its own | Needs a fresh human approval; with no human reachable the result is deny. |
| Audit records are edited, reordered or removed from the middle | `ecv audit --verify` fails. |
| A session outlives its purpose | The key is zeroed at TTL; the next call must re-authenticate. |

## What ECV does **not** protect against

- **Plaintext you create.** `ecv checkout`, a build directory, an editor buffer or
  an agent's own context window all hold decrypted code. Once an agent has read a file
  through the gateway it has seen that file; ECV limits *which* files and *how often*,
  and records it, but cannot un-read it. Do not grant `read` on code you would not
  want that agent to see.
- **A process running as you with debug rights.** Malware or an agent with your
  privileges can read the gateway's memory or run `ecv` and wait for you to approve a
  prompt. macOS SIP and hardened runtime raise the bar; they do not remove it.
- **A compromised terminal or a fake prompt.** Approvals show the request text, but you
  must read it.
- **Memory hygiene guarantees.** Keys are zeroed on close, but JavaScript may leave
  copies (GC moves, swap, core dumps). Native key handling is on the roadmap.
- **Rollback of the whole vault.** Restoring an older complete copy of the vault
  directory is not detected without external state (e.g. a signed tag or remote counter).
- **Truncating the end of the audit log.** The chain proves internal consistency, not
  completeness. Anchor it off-machine for stronger guarantees.
- **Metadata.** The number of files, their approximate sizes and modification times of
  the vault files are visible on disk.
- **Weak passphrases.** scrypt slows guessing, it does not stop it. The 12-character
  minimum is a floor, not a recommendation; the recovery code has 160 bits of entropy.

## Touch ID in v0.1 — an honest note

The macOS helper authenticates you with `LocalAuthentication` (Touch ID, falling back
to the account password) and only then releases a random device secret from the login
Keychain. This is a **presence gate**: a process running as you that can read your
Keychain item bypasses the prompt. It is meaningfully better than a typed passphrase in
a script, but weaker than a hardware-bound key.

The Secure Enclave design — a non-exportable key whose use requires biometrics —
needs a signed helper with Keychain entitlements (Apple Developer ID). It is the first
item on the [roadmap](PRODUCT.md), and the key-slot format already supports it without
migration.

## Reporting vulnerabilities

Until a security contact is published, please open a private security advisory on the
repository rather than a public issue.
