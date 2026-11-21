// OAuth 2.0 protocol pieces: error responses (RFC 6749) and PKCE (RFC 7636).

import { createHash, timingSafeEqual } from "node:crypto";
import { HttpError } from "../shared/http.js";

export type OAuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "unsupported_response_type"
  | "invalid_scope"
  | "access_denied";

/** HttpError restricted to the RFC 6749 §5.2 error codes. */
export class OAuthError extends HttpError {
  constructor(error: OAuthErrorCode, description: string, statusCode: 400 | 401 = 400) {
    super(statusCode, description, error);
  }
}

/** PKCE code_verifier: 43-128 chars of [A-Z a-z 0-9 - . _ ~] (RFC 7636 §4.1). */
const PKCE_VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;

/** PKCE S256: BASE64URL(SHA256(ASCII(code_verifier))) === code_challenge (RFC 7636 §4.6), compared in constant time. */
export function verifyPkceS256(verifier: string, challenge: string): boolean {
  if (!PKCE_VERIFIER_RE.test(verifier)) return false;
  const computed = Buffer.from(createHash("sha256").update(verifier).digest("base64url"));
  const expected = Buffer.from(challenge);
  return computed.length === expected.length && timingSafeEqual(computed, expected);
}
