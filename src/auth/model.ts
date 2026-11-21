// Auth domain model: users, their credentials, and the OAuth / WebAuthn records the server keeps.
// Pure types — no storage or transport concerns (see repository.ts for persistence).

import type { HashAlgorithm } from "../shared/hashing.js";

export interface User {
  id: string;
  username: string;
  /** Every way this user can authenticate. A user always keeps at least one. */
  credentials: Credential[];
  createdAt: Date;
}


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
}
