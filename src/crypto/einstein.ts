import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { IntegrityError } from "../errors.js";

export const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const SCRYPT_MAX_MEMORY = 256 * 1024 * 1024;

export interface ScryptParams {
  alg: "scrypt";
  N: number;
  r: number;
  p: number;
  /** base64 */
  salt: string;
}

/** 128 MiB of memory per guess (128 * N * r bytes). */
export const DEFAULT_SCRYPT = { N: 1 << 17, r: 8, p: 1 } as const;

export function randomKey(): Buffer {
  return randomBytes(KEY_BYTES);
}

/** HKDF-SHA256. `info` provides domain separation between key purposes. */
export function einsteinDerive(secret: Uint8Array, info: string, salt: Uint8Array = new Uint8Array(0)): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, salt, info, KEY_BYTES));
}

/** AES-256-GCM. Output layout: nonce (12) | ciphertext | tag (16). */
export function seal(key: Buffer, plaintext: Uint8Array, aad: string): Buffer {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
}

export function open(key: Buffer, blob: Uint8Array, aad: string): Buffer {
  if (blob.length < NONCE_BYTES + TAG_BYTES) {
    throw new IntegrityError("ciphertext is truncated");
  }
  const buf = Buffer.from(blob.buffer, blob.byteOffset, blob.byteLength);
  const nonce = buf.subarray(0, NONCE_BYTES);
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const ciphertext = buf.subarray(NONCE_BYTES, buf.length - TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new IntegrityError("authentication failed");
  }
}

export function newScryptParams(overrides: Partial<Pick<ScryptParams, "N" | "r" | "p">> = {}): ScryptParams {
  return { alg: "scrypt", ...DEFAULT_SCRYPT, ...overrides, salt: randomBytes(16).toString("base64") };
}

export function stretchPassphrase(passphrase: string, params: ScryptParams): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(
      passphrase.normalize("NFKC"),
      Buffer.from(params.salt, "base64"),
      KEY_BYTES,
      { N: params.N, r: params.r, p: params.p, maxmem: SCRYPT_MAX_MEMORY },
      (error, key) => (error ? reject(error) : resolve(key)),
    );
  });
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of text) {
    const index = BASE32.indexOf(ch);
    if (index < 0) throw new IntegrityError("invalid base32 character");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}
