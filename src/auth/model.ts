// Auth domain model: users, their credentials, and the OAuth / WebAuthn records the server keeps.
// Pure types — no storage or transport concerns (see repository.ts for persistence).

import type { HashAlgorithm } from "../shared/hashing.js";

export interface User {
  id: string;
  username: string;
  /** Lowercased, unique. Optional only for accounts created before email was collected. */
  email?: string;
  /** When `email` was last proven to belong to the user (emailed code). Unset = unverified. */
  emailVerifiedAt?: Date;
  /** Per-language profile (name, ...) in one or more languages; at most one entry per `lang`. */
  profiles: LocalizedProfile[];
  /** Language of the profile to display; always one of `profiles[].lang` when set. */
  preferredLang?: string;
  /** Every way this user can authenticate. A user always keeps at least one. */
  credentials: Credential[];
  /** Authorization roles; empty for regular users. */
  roles: Role[];
  createdAt: Date;
}

export const ROLES = ["admin"] as const;
export type Role = (typeof ROLES)[number];

/** Lightweight user row for admin listings (no profiles or credentials). */
export interface UserSummary {
  id: string;
  username: string;
  email?: string;
  roles: Role[];
  createdAt: Date;
}

export interface LocalizedProfile {
  /** BCP 47 language tag, e.g. "th", "en", "en-US". */
  lang: string;
  firstName: string;
  lastName: string;
}

/** Account fields a user can change; omitted fields stay as they are, `preferredLang: null` clears it. */
export interface AccountUpdate {
  email?: string;
  /** Set by the service, never by the client: `null` marks the (new) email unverified. */
  emailVerifiedAt?: Date | null;
  profiles?: LocalizedProfile[];
  preferredLang?: string | null;
}

/** Profile in the preferred language, else the first one available. */
export const displayProfile = (user: Pick<User, "profiles" | "preferredLang">): LocalizedProfile | undefined =>
  user.profiles.find((p) => p.lang === user.preferredLang) ?? user.profiles[0];

/**
 * Knowledge factors: something the user knows, stored only as a hash.
 * To add one (e.g. "pin"): extend this union, then the DB constraints (Postgres CHECK) and its own policy
 * (length rules, attempt limits) in the service. Hashing/verification is shared.
 */
export type SecretType = "password";

interface CredentialBase {
  id: string;
  createdAt: Date;
  lastUsedAt?: Date;
}

export interface SecretCredential extends CredentialBase {
  type: SecretType;
  value: string; // encoded hash (PHC string), never the plain secret
  algorithm: HashAlgorithm;
}

export interface PasswordCredential extends SecretCredential {
  type: "password";
}

export interface WebAuthnCredential extends CredentialBase {
  type: "webauthn";
  webauthn: WebAuthnData;
}

export type Credential = SecretCredential | WebAuthnCredential;

export interface WebAuthnData {
  credId: string; // base64url, globally unique
  publicKeyPem: string;
  counter: number;
  transports?: string[];
  name: string;
}

export const isSecret = (c: Credential): c is SecretCredential => c.type !== "webauthn";
export const isPassword = (c: Credential): c is PasswordCredential => c.type === "password";
export const isWebAuthn = (c: Credential): c is WebAuthnCredential => c.type === "webauthn";

export interface WebAuthnChallenge {
  id: string;
  type: "register" | "login";
  challenge: string; // base64url
  userId?: string;
  authRequestId?: string;
  expiresAt: Date;
}

export interface AuthRequest {
  id: string;
  clientId: string;
  redirectUri: string;
  state?: string;
  scope: string;
  codeChallenge: string;
  /** OIDC: echoed into the ID Token to bind it to this request. */
  nonce?: string;
  expiresAt: Date;
}

export interface AuthCode {
  id: string; // sha256(code)
  userId: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string;
  familyId: string; // tokens issued from this code share it (replay => revoke)
  nonce?: string;
  /** When the user authenticated (ID Token auth_time). Optional only for rows written before OIDC. */
  authTime?: Date;
  /** Device the user signed in from; carried into the tokens so a device can be signed out. */
  deviceId?: string;
  used: boolean;
  expiresAt: Date;
}

export interface AccessToken {
  id: string; // sha256(token)
  userId: string;
  clientId: string;
  scope: string;
  familyId: string;
  /** Device that signed in (absent for tokens issued before devices were tracked). */
  deviceId?: string;
  expiresAt: Date;
}

export interface RefreshToken extends AccessToken {
  revoked: boolean;
  /** Original authentication time, carried into ID Tokens issued on refresh. */
  authTime?: Date;
}

// ---------------------------------------------------------------- email codes

/**
 * "signin": a step of the login page, bound to an authorization request — confirming it signs the user in.
 * "verify": only proves the address (account page / API registration); confirming it signs nobody in.
 */
export type EmailChallengePurpose = "signin" | "verify";
/** Why the code was sent: picks the email wording and the sign-in method recorded for the device. */
export type EmailChallengeReason = "register" | "verify_email" | "login";

/**
 * "code": a 6-digit code typed into the page that asked for it.
 * "link": a link with a 256-bit token; opening it (any browser/device) approves the challenge, and the page
 * that asked for it notices by polling and finishes there (it holds the PKCE verifier / session).
 */
export const EMAIL_VERIFICATION_METHODS = ["code", "link"] as const;
export type EmailVerificationMethod = (typeof EMAIL_VERIFICATION_METHODS)[number];

/** A one-time code or link sent to an email address. Only a hash of the code / link token is stored. */
export interface EmailChallenge {
  id: string;
  purpose: EmailChallengePurpose;
  reason: EmailChallengeReason;
  /** Fixed when the challenge is created, so changing the config does not break pending ones. */
  method: EmailVerificationMethod;
  userId: string;
  /** Address the code went to; it is marked verified only if the user still has this address. */
  email: string;
  /** OAuth client the user was signing in to (sign-in challenges): where an emailed link continues. */
  clientId?: string;
  /** sha256 of the code (method "code") or link token (method "link"). */
  codeHash: string;
  /** Link opened and confirmed; waiting for the requesting page to pick it up (method "link"). */
  approvedAt?: Date;
  /** Wrong codes entered so far. */
  attempts: number;
  /** Times a code was emailed for this challenge (first send + resends). */
  sends: number;
  sentAt: Date;
  authRequestId?: string;
  expiresAt: Date;
}

// ---------------------------------------------------------------- devices

export const SIGN_IN_METHODS = ["password", "password+email_code", "password+email_link", "passkey", "registration"] as const;
export type SignInMethod = (typeof SIGN_IN_METHODS)[number];

/**
 * A browser a user has signed in from. Recognized by a random key in an httpOnly cookie (only its hash
 * is stored), so one record per (user, browser).
 */
export interface Device {
  id: string;
  userId: string;
  /** sha256 of the device cookie. */
  keyHash: string;
  /** Human-readable, e.g. "Chrome on macOS" (derived from the User-Agent). */
  name: string;
  userAgent: string;
  /** Client address of the latest sign-in. */
  ip?: string;
  /** First sign-in from this device. */
  createdAt: Date;
  lastSignInAt: Date;
  /** Latest sign-in or token refresh. */
  lastSeenAt: Date;
  lastMethod: SignInMethod;
  signIns: number;
}

/** What a sign-in records about the device (`id` is used only when the device is new). */
export interface DeviceSignIn {
  id: string;
  userId: string;
  keyHash: string;
  name: string;
  userAgent: string;
  ip?: string;
  at: Date;
  method: SignInMethod;
}

// ---------------------------------------------------------------- OAuth clients

/** RFC 7591 §2 token_endpoint_auth_method: "none" = public client (PKCE only), else confidential. */
export const TOKEN_ENDPOINT_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"] as const;
export type TokenEndpointAuthMethod = (typeof TOKEN_ENDPOINT_AUTH_METHODS)[number];

export const CLIENT_GRANT_TYPES = ["authorization_code", "refresh_token"] as const;
export type ClientGrantType = (typeof CLIENT_GRANT_TYPES)[number];

/**
 * A registered OAuth 2.0 / OpenID Connect client (RFC 6749 §2, RFC 7591 metadata), plus per-client
 * settings that used to be server-wide env vars (token lifetimes, how emails verify the user).
 */
export interface OAuthClient {
  /** client_id */
  id: string;
  /** client_name — also shown in emails sent for this client. */
  name: string;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  /** sha256 of the client_secret (confidential clients only; the secret is shown once). */
  secretHash?: string;
  /** Exact-match list (RFC 6749 §3.1.2.2); https, or http on loopback for development. */
  redirectUris: string[];
  grantTypes: ClientGrantType[];
  /** Space-separated scopes the client may request; also the default when a request names none. */
  scope: string;
  /** client_uri: home page of the client. */
  clientUri?: string;
  /**
   * OIDC initiate_login_uri (Third-Party Initiated Login, OIDC Core §4): where an emailed sign-in link sends
   * the browser so the client starts a fresh authorization request and the user ends up signed in there.
   */
  initiateLoginUri?: string;
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
  idTokenTtlSec: number;
  /** How emails sent for this client verify the user: 6-digit code or link. */
  emailVerification: EmailVerificationMethod;
  createdAt: Date;
  updatedAt: Date;
}
