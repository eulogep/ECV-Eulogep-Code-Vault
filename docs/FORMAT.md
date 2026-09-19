# Vault format v1

This page specifies the on-disk format so that independent implementations can be
written and audited. All multi-byte values are raw bytes; "b64" is standard base64.

## Layout

```
<vault>/
  vault.json      plaintext header: format, version, id, createdAt, key slots
  manifest.enc    AES-256-GCM sealed JSON: file index + policy
  objects/<id>.enc  one sealed object per file version (id = 16 random bytes, hex)
  audit.log       one base64 sealed record per line, hash-chained
  .lock           transient lock file (O_EXCL)
```

## Primitives

| Purpose | Algorithm |
| --- | --- |
| Encryption | AES-256-GCM, 96-bit random nonce, 128-bit tag |
| Key derivation | HKDF-SHA256 (32-byte output), `info` for domain separation |
| Passphrase stretching | scrypt (N, r, p and 16-byte salt stored in the slot) |
| Hashes | SHA-256 |

`seal(key, plaintext, aad)` output is `nonce(12) || ciphertext || tag(16)`.
`aad` is the UTF-8 bytes of the string given below.

## Key hierarchy

```
master key K (32 random bytes)
 ├─ manifest key = HKDF(K, info="ecv/manifest/v1")
 ├─ audit key    = HKDF(K, info="ecv/audit/v1")
 └─ object key   = HKDF(K, salt=objectSalt, info="ecv/object/v1/" + objectId)
```

K is never stored in the clear. It is wrapped by each key slot.

## Key slots (`vault.json`)

Each slot stores `wrapped = b64(seal(KEK, K, aad = "ecv/slot/v1|" + vaultId + "|" + slotId))`.

| Slot type | KEK |
| --- | --- |
| `passphrase` | `HKDF(scrypt(NFKC(passphrase), salt, N, r, p), info="ecv/kek/passphrase/v1")` |
| `recovery` | `HKDF(base32decode(code), info="ecv/kek/recovery/v1")`; code = 20 random bytes, RFC 4648 base32, shown in groups of 4 |
| `device` | `HKDF(deviceSecret, info="ecv/kek/device/v1")`; the 32-byte secret is released by a local authenticator |

Readers must reject headers that are not valid JSON, have no slots, or carry scrypt
parameters outside: N a power of two ≥ 2^10, 1 ≤ r ≤ 16, 1 ≤ p ≤ 16, and
128·N·r ≤ 256 MiB. The header is unauthenticated, so this check protects against
resource exhaustion; forged slots cannot wrap K without the KEK.

## Manifest (`manifest.enc`)

`seal(manifestKey, JSON, aad = "ecv/manifest/v1|" + vaultId)`. JSON fields: `version`,
`seq` (incremented on every change), `files` (array of `[path, {object, size, mtimeMs,
sha256}]`; an array, not an object, so paths such as `__proto__` are safe) and `policy`.

## Objects

`"ECV1" || salt(32) || seal(objectKey, plaintext, aad = "ecv/object/v1|" + objectId)`

Every write creates a new object id and then swaps the manifest entry, so a crash
leaves at worst an unreferenced object (`Vault.collectGarbage` removes it). On read the
plaintext SHA-256 must equal the manifest entry.

## Audit log

Each line is `b64(seal(auditKey, JSON, aad = "ecv/audit/v1|" + vaultId))`. A record has
`seq`, `ts`, `prev` (SHA-256 hex of the previous *line*, 64 zeros for the first),
`actor`, `action`, optional `path`/`detail`, and `decision`. Verification decrypts every
line and checks `seq` and `prev`.

## Paths

Canonical form: Unicode NFC, `\` treated as `/`, relative, no `.` or empty segments,
`..` rejected, no control characters, at most 1024 characters.

## Known-answer vectors

Master key `K = 0x01 × 32`:

| Item | Value |
| --- | --- |
| `HKDF(K, "ecv/manifest/v1")` | `827b2f4577c7b7b46559f43468c6a7044740bda42e9784cef754aa279d04ccbe` |
| `HKDF(K, "ecv/audit/v1")` | `835dff132ccd471bb64f72fb225deb0f250626d9cf624da5f6923a5adce79e67` |
| `HKDF(K, salt=0x02×32, "ecv/object/v1/00112233445566778899aabbccddeeff")` | `33c7024404c156a430b668b54ca60fd1784a7d94901af1b7a6fe0a8f531b5d22` |

Passphrase `correct horse battery staple`, scrypt N=1024 r=8 p=1, salt `0x03 × 16`:

| Item | Value |
| --- | --- |
| scrypt output | `0cb80b8b9eefd276677a912338f8221ff00175c7e7a28a9af93a7689324fde7f` |
| passphrase KEK | `23ea631a4bafe64f1c26ccb6ab1049fba9d51288afac05d153c446ee0dc9d806` |

Recovery code `AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH`:

| Item | Value |
| --- | --- |
| decoded bytes | `00000084211084218c6321084294a5318c639ce7` |
| recovery KEK | `f04cd50e35aa251192f7ef0bf9aca4a3ea4ce69c15447e353cc70b6dac13c6b6` |

These were cross-checked against an independent implementation (Python `hashlib.scrypt`
and an HMAC-based HKDF) and are enforced by `src/crypto/vectors.test.ts`.

## Compatibility

`version` in `vault.json` is 1. A reader must refuse any other value. Changing any
`info`/`aad` string or layout above requires a new version.
