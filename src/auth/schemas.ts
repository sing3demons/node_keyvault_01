// Request schemas for the auth endpoints. Types are inferred from these, so what the handlers
// receive is exactly what was validated — no casts or non-null assertions downstream.

import { z } from "zod";
import { formatZodError } from "../shared/http.js";
import { ROLES } from "./model.js";
import { OAuthError } from "./oauth.js";

const nonEmpty = z.string().min(1);
const base64url = z.string().regex(/^[A-Za-z0-9_-]+$/, "must be base64url");
/**
 * Username or email address (it is an email when it contains "@"). Only normalized, not pattern-checked,
 * so errors never hint which accounts exist.
 */
const loginIdentifier = z.string().trim().toLowerCase().min(1).max(254);

// ---------------------------------------------------------------- profile fields

/** BCP 47 language tag, canonicalized (e.g. "EN-us" -> "en-US") so one language is never stored twice. */
const langTag = z.string().transform((value, ctx) => {
  try {
    const [canonical] = Intl.getCanonicalLocales(value.trim());
    if (canonical) return canonical;
  } catch {
    // invalid tag, reported below
  }
  ctx.addIssue({ code: "custom", message: "lang must be a BCP 47 language tag, e.g. th, en, en-US" });
  return z.NEVER;
});

const email = z.string().trim().toLowerCase().pipe(z.email("email must be a valid email address").max(254));

const localizedProfile = z.object({
  lang: langTag,
  firstName: z.string().trim().min(1, "firstName is required").max(100),
  lastName: z.string().trim().min(1, "lastName is required").max(100)
});

const profiles = z
  .array(localizedProfile)
  .min(1, "at least one profile is required")
  .max(20)
  .refine((list) => new Set(list.map((n) => n.lang)).size === list.length, "each lang may appear only once");

/** preferredLang must be one of the user's profile languages. */
const preferredLangInProfiles = (v: { profiles?: { lang: string }[]; preferredLang?: string | null }) =>
  !v.profiles || !v.preferredLang || v.profiles.some((n) => n.lang === v.preferredLang);
const preferredLangIssue = { message: "preferredLang must be one of profiles[].lang", path: ["preferredLang"] };

// ---------------------------------------------------------------- /auth

export const registerBody = z
  .object({
    /** From the login page: entering the emailed code then also signs the new user in. */
    request_id: nonEmpty.optional(),
    username: z
      .string()
      .trim()
      .toLowerCase()
      .regex(/^[a-z0-9_.-]{3,32}$/, "Username must be 3-32 chars: a-z, 0-9, _ . -"),
    email,
    password: z.string().min(8, "Password must be 8-256 characters").max(256, "Password must be 8-256 characters"),
    profiles,
    preferredLang: langTag.optional()
  })
  .refine(preferredLangInProfiles, preferredLangIssue);

/** PATCH /auth/me — every field optional; `preferredLang: null` clears the choice. */
export const updateAccountBody = z
  .object({
    email: email.optional(),
    profiles: profiles.optional(),
    preferredLang: langTag.nullable().optional()
  })
  .refine((v) => Object.values(v).some((x) => x !== undefined), "nothing to update")
  .refine(preferredLangInProfiles, preferredLangIssue);

export const passwordLoginBody = z.object({
  request_id: nonEmpty,
  /** Username or email (signing in with an email also requires a code sent to it). */
  username: loginIdentifier,
  password: z.string().max(256)
});

/** POST /auth/email/verify — `request_id` only for codes started on the login page (sign-in). */
export const emailCodeBody = z.object({
  challengeId: nonEmpty.max(64),
  code: z
    .string()
    .transform((v) => v.replace(/[\s-]/g, ""))
    .pipe(z.string().regex(/^\d{6}$/, "code must be the 6 digits from the email")),
  request_id: nonEmpty.optional()
});

export const emailResendBody = z.object({ challengeId: nonEmpty.max(64) });

/** POST /auth/email/link — from the page the emailed link opens. */
export const emailLinkBody = z.object({
  challengeId: nonEmpty.max(64),
  token: base64url.max(64)
});

/** POST /auth/email/status — polled by the page waiting for its link to be opened. */
export const emailStatusBody = z.object({
  challengeId: nonEmpty.max(64),
  request_id: nonEmpty.optional()
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

// ---------------------------------------------------------------- /admin

export const usernameParam = z.object({ username: z.string().trim().toLowerCase().min(1).max(64) });

/** PUT /admin/users/:username/roles — the complete new role list ([] = regular user). */
export const setRolesBody = z.object({ roles: z.array(z.enum(ROLES)).max(ROLES.length) });

export type RegisterBody = z.infer<typeof registerBody>;
export type UpdateAccountBody = z.infer<typeof updateAccountBody>;
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
  code_challenge_method: z.string().optional(),
  nonce: z.string().max(512).optional()
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
