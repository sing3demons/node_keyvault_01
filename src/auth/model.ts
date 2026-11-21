// Auth domain model: users, their credentials, and the OAuth / WebAuthn records the server keeps.
// Pure types — no storage or transport concerns (see repository.ts for persistence).

import type { HashAlgorithm } from "../shared/hashing.js";

export interface User {
  id: string;
  username: string;
  /** Lowercased, unique. Optional only for accounts created before email was collected. */
  email?: string;
  /** Per-language profile (name, ...) in one or more languages; at most one entry per `lang`. */
  profiles: LocalizedProfile[];
  /** Language of the profile to display; always one of `profiles[].lang` when set. */
  preferredLang?: string;
  /** Every way this user can authenticate. A user always keeps at least one. */
  credentials: Credential[];
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
  used: boolean;
  expiresAt: Date;
}

export interface AccessToken {
  id: string; // sha256(token)
  userId: string;
  clientId: string;
  scope: string;
  familyId: string;
  expiresAt: Date;
}

export interface RefreshToken extends AccessToken {
  revoked: boolean;
  /** Original authentication time, carried into ID Tokens issued on refresh. */
  authTime?: Date;
}
