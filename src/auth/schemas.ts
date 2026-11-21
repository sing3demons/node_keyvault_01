// Request schemas for the auth endpoints. Types are inferred from these, so what the handlers
// receive is exactly what was validated — no casts or non-null assertions downstream.

import { z } from "zod";
import { formatZodError } from "../shared/http.js";
import { OAuthError } from "./oauth.js";

const nonEmpty = z.string().min(1);
const base64url = z.string().regex(/^[A-Za-z0-9_-]+$/, "must be base64url");
/** Login input is only normalized (not pattern-checked) so errors never hint which usernames exist. */
const loginUsername = z.string().trim().toLowerCase().min(1).max(64);

// ---------------------------------------------------------------- /auth

export const registerBody = z.object({
  username: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^[a-z0-9_.-]{3,32}$/, "Username must be 3-32 chars: a-z, 0-9, _ . -"),
  password: z.string().min(8, "Password must be 8-256 characters").max(256, "Password must be 8-256 characters")
});

export const passwordLoginBody = z.object({
  request_id: nonEmpty,
  username: loginUsername,
  password: z.string().max(256)
});

export const passkeyLoginOptionsBody = z.object({
  request_id: nonEmpty
});

/** PublicKeyCredential as JSON (binary fields base64url). */
const credentialBase = {
  id: base64url,
  rawId: base64url,
  type: z.literal("public-key")
};

export const attestationCredential = z.object({
  ...credentialBase,
  transports: z.array(z.string()).optional(),
  response: z.object({
    clientDataJSON: base64url,
    attestationObject: base64url
  })
});

export const assertionCredential = z.object({
  ...credentialBase,
  response: z.object({
    clientDataJSON: base64url,
    authenticatorData: base64url,
    signature: base64url,
    userHandle: base64url.nullish()
  })
});

export const passkeyLoginVerifyBody = z.object({
  request_id: nonEmpty,
  challengeId: nonEmpty,
  credential: assertionCredential
});

export const passkeyRegisterVerifyBody = z.object({
  challengeId: nonEmpty,
  name: z.string().trim().max(64).optional(),
  credential: attestationCredential
});

export const credentialIdParam = z.object({
  id: nonEmpty
});

export type RegisterBody = z.infer<typeof registerBody>;
export type AttestationCredential = z.infer<typeof attestationCredential>;
export type AssertionCredential = z.infer<typeof assertionCredential>;

// ---------------------------------------------------------------- /oauth

/** Authorization request. Fields stay optional: the service reports OAuth errors itself (some by redirect). */
export const authorizeQuery = z.object({
  response_type: z.string().optional(),
  client_id: z.string().optional(),
  redirect_uri: z.string().optional(),
  state: z.string().optional(),
  scope: z.string().optional(),
  code_challenge: z.string().optional(),
  code_challenge_method: z.string().optional()
});

/** Token request (RFC 6749 §4.1.3, §6), discriminated by grant_type. */
export const tokenBody = z.discriminatedUnion("grant_type", [
  z.object({
    grant_type: z.literal("authorization_code"),
    code: nonEmpty,
    redirect_uri: nonEmpty,
    client_id: nonEmpty,
    code_verifier: nonEmpty
  }),
  z.object({
    grant_type: z.literal("refresh_token"),
    refresh_token: nonEmpty,
    client_id: nonEmpty,
    scope: z.string().optional()
  })
]);

export const revokeBody = z.object({
  token: z.string().optional(),
  token_type_hint: z.string().optional()
});

/** Token endpoint errors must use the RFC 6749 §5.2 shape, so validation failures become OAuthError. */
export function parseTokenRequest(form: Record<string, unknown>): z.output<typeof tokenBody> {
  const result = tokenBody.safeParse(form);
  if (result.success) return result.data;
  const grantType = form.grant_type;
  if (grantType === undefined || grantType === "") {
    throw new OAuthError("invalid_request", "grant_type is required");
  }
  if (grantType !== "authorization_code" && grantType !== "refresh_token") {
    throw new OAuthError("unsupported_grant_type", "Supported: authorization_code, refresh_token");
  }
  throw new OAuthError("invalid_request", formatZodError(result.error));
}
