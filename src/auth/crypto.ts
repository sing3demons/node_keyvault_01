import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** Random URL-safe token (default 32 bytes = 256 bits). */
export const randomToken = (bytes = 32): string => randomBytes(bytes).toString("base64url");

/** Tokens/codes are stored only as SHA-256 hashes. */
export const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

/** RFC 7636 S256: BASE64URL(SHA256(ASCII(code_verifier))) === code_challenge */
export function verifyPkceS256(verifier: string, challenge: string): boolean {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return false;
  const computed = Buffer.from(createHash("sha256").update(verifier).digest("base64url"));
  const expected = Buffer.from(challenge);
  return computed.length === expected.length && timingSafeEqual(computed, expected);
}

export const toBase64Url = (data: ArrayBuffer | Uint8Array): string =>
  Buffer.from(data instanceof ArrayBuffer ? new Uint8Array(data) : data).toString("base64url");

export function fromBase64Url(value: string): ArrayBuffer {
  const buf = Buffer.from(value, "base64url");
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}
