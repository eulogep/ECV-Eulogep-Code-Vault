import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { base32Decode, einsteinDerive, stretchPassphrase } from "./einstein.js";

// Known-answer vectors, cross-checked against an independent implementation
// (Python hashlib.scrypt + HMAC-based HKDF). They are also published in docs/FORMAT.md:
// a change here means the on-disk format changed.
const hex = (buffer: Uint8Array): string => Buffer.from(buffer).toString("hex");
const master = Buffer.alloc(32, 0x01);

describe("format known-answer vectors", () => {
  it("derives the manifest and audit keys", () => {
    assert.equal(hex(einsteinDerive(master, "ecv/manifest/v1")), "827b2f4577c7b7b46559f43468c6a7044740bda42e9784cef754aa279d04ccbe");
    assert.equal(hex(einsteinDerive(master, "ecv/audit/v1")), "835dff132ccd471bb64f72fb225deb0f250626d9cf624da5f6923a5adce79e67");
  });

  it("derives a per-object key from master key, object id and salt", () => {
    const key = einsteinDerive(master, "ecv/object/v1/00112233445566778899aabbccddeeff", Buffer.alloc(32, 0x02));
    assert.equal(hex(key), "33c7024404c156a430b668b54ca60fd1784a7d94901af1b7a6fe0a8f531b5d22");
  });

  it("derives the passphrase key-encryption key", async () => {
    const stretched = await stretchPassphrase("correct horse battery staple", {
      alg: "scrypt",
      N: 1024,
      r: 8,
      p: 1,
      salt: Buffer.alloc(16, 0x03).toString("base64"),
    });
    assert.equal(hex(stretched), "0cb80b8b9eefd276677a912338f8221ff00175c7e7a28a9af93a7689324fde7f");
    assert.equal(hex(einsteinDerive(stretched, "ecv/kek/passphrase/v1")), "23ea631a4bafe64f1c26ccb6ab1049fba9d51288afac05d153c446ee0dc9d806");
  });

  it("derives the recovery key-encryption key from a recovery code", () => {
    const bytes = base32Decode("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH");
    assert.equal(hex(bytes), "00000084211084218c6321084294a5318c639ce7");
    assert.equal(hex(einsteinDerive(bytes, "ecv/kek/recovery/v1")), "f04cd50e35aa251192f7ef0bf9aca4a3ea4ce69c15447e353cc70b6dac13c6b6");
  });
});
