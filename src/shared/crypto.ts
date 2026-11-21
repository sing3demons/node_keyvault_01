// Random tokens, hashing and binary encodings.

import { createHash, randomBytes } from "node:crypto";

/** Random URL-safe token (default 32 bytes = 256 bits). */
export const randomToken = (bytes = 32): string => randomBytes(bytes).toString("base64url");

/** Tokens/codes are stored only as SHA-256 hashes. */
export const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

/** Bytes -> base64url string (no padding). */
export const toBase64Url = (data: ArrayBuffer | Uint8Array): string =>
  Buffer.from(data instanceof ArrayBuffer ? new Uint8Array(data) : data).toString("base64url");

/** base64url string -> standalone ArrayBuffer (not a view into Node's shared Buffer pool). */
export function fromBase64Url(value: string): ArrayBuffer {
  const buf = Buffer.from(value, "base64url");
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}
