// OpenID Connect on top of the OAuth server: signed ID Tokens (OIDC Core §2), the public keys
// to verify them (JWKS) and the discovery document (OIDC Discovery §3).
//
// Signing keys rotate. The key set lives in a SigningKeyStore (Azure Key Vault in this app):
//   active  - the one key that signs new ID Tokens
//   retired - no longer signs; still published in the JWKS until `expiresAt`, so tokens it signed
//             keep verifying. Its private key is dropped the moment it is retired.

import { createHash } from "node:crypto";
import {
  calculateJwkThumbprint,
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  importPKCS8,
  SignJWT,
  type CryptoKey,
  type JWK
} from "jose";
import { z } from "zod";
import { errorMessage } from "../shared/util.js";

export interface OidcSettings {
  /** How often `init()`-ed rings reload the key set from the store (and rotate when due). */
  keysSyncSec: number;
  /** Issuer identifier: an https URL in production, e.g. https://auth.example.com */
  issuer: string;
  idTokenTtlSec: number;
  /** Rotate when the active key is older than this. */
  keyRotationDays: number;
  /** How long a retired key stays in the JWKS (must exceed ID Token lifetime + client JWKS caching). */
  retiredKeyGraceSec: number;
}

/** Scopes defined by OIDC Core §5.4 that this server supports. */
export const OIDC_SCOPES = ["openid", "profile", "email"] as const;

const ALG = "RS256"; // the one algorithm OIDC requires every provider to support
const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth"] as const;
const DAY_MS = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------- stored key set

const publicJwkSchema = z
  .object({ kty: z.literal("RSA"), n: z.string(), e: z.string(), kid: z.string(), alg: z.literal(ALG), use: z.literal("sig") })
  .strict();

const signingKeySchema = z.discriminatedUnion("status", [
  z.object({
    status: z.literal("active"),
    kid: z.string(),
    createdAt: z.iso.datetime(),
    publicJwk: publicJwkSchema,
    privateKeyPem: z.string().startsWith("-----BEGIN PRIVATE KEY-----")
  }),
  z.object({
    status: z.literal("retired"),
    kid: z.string(),
    createdAt: z.iso.datetime(),
    publicJwk: publicJwkSchema,
    retiredAt: z.iso.datetime(),
    /** Removed from the JWKS after this. */
    expiresAt: z.iso.datetime()
  })
]);

const keySetSchema = z.object({ version: z.literal(1), keys: z.array(signingKeySchema) });

export type SigningKeyRecord = z.infer<typeof signingKeySchema>;
export type SigningKeySet = z.infer<typeof keySetSchema>;

/** Where the key set is persisted. `load` returns null when nothing is stored yet. */
export interface SigningKeyStore {
  load(): Promise<string | null>;
  save(value: string): Promise<void>;
}

/**
 * Holds the signing keys in memory, backed by a SigningKeyStore so every instance shares them.
 * `init()` loads them and keeps them in sync (reload + rotate when due) until `close()`.
 * One-off tools (e.g. the rotate CLI) can call `rotate()` without `init()` — no timer is started.
 */
export class SigningKeyRing {
  private keys: SigningKeyRecord[] = [];
  private active?: { kid: string; privateKey: CryptoKey };
  private syncTimer?: NodeJS.Timeout;

  constructor(
    private readonly store: SigningKeyStore,
    private readonly settings: Pick<OidcSettings, "keyRotationDays" | "retiredKeyGraceSec" | "keysSyncSec">
  ) {}

  /** First sync (fails loudly if keys cannot be loaded), then periodic background syncs. */
  async init(): Promise<void> {
    await this.sync();
    this.syncTimer ??= setInterval(
      () => this.sync().catch((e) => console.error("OIDC key sync failed", e)),
      this.settings.keysSyncSec * 1000
    ).unref();
  }

  close(): void {
    clearInterval(this.syncTimer);
    this.syncTimer = undefined;
  }

  /** Load the stored set (creating the first key if there is none) and rotate if due. */
  async sync(now = new Date()): Promise<void> {
    await this.reload();
    const current = this.keys.find((k) => k.status === "active");
    const age = current ? now.getTime() - Date.parse(current.createdAt) : Infinity;
    if (age >= this.settings.keyRotationDays * DAY_MS) {
      await this.rotate(now);
    }
  }

  /**
   * New active key; the current one becomes retired (public part only) until the grace period ends.
   * Expired retired keys are dropped. Re-reads the store first to build on the latest set.
   */
  async rotate(now = new Date()): Promise<{ kid: string; retired: string[] }> {
    await this.reload();
    return this.rotateLoaded(now);
  }

  /** Rotation on top of the keys already in memory (no reload). */
  private async rotateLoaded(now: Date): Promise<{ kid: string; retired: string[] }> {
    const { privateKey } = await generateKeyPair(ALG, { extractable: true, modulusLength: 2048 });
    const jwk = await exportJWK(privateKey);
    for (const field of PRIVATE_JWK_FIELDS) delete jwk[field];
    const kid = await calculateJwkThumbprint(jwk);
    const next: SigningKeyRecord = {
      status: "active",
      kid,
      createdAt: now.toISOString(),
      publicJwk: { kty: "RSA", n: jwk.n!, e: jwk.e!, kid, alg: ALG, use: "sig" },
      privateKeyPem: await exportPKCS8(privateKey)
    };
    const expiresAt = new Date(now.getTime() + this.settings.retiredKeyGraceSec * 1000).toISOString();
    const kept = this.keys
      .map((k): SigningKeyRecord =>
        k.status === "active"
          ? { status: "retired", kid: k.kid, createdAt: k.createdAt, publicJwk: k.publicJwk, retiredAt: now.toISOString(), expiresAt }
          : k
      )
      .filter((k) => k.status !== "retired" || Date.parse(k.expiresAt) > now.getTime());
    const set: SigningKeySet = { version: 1, keys: [next, ...kept] };
    await this.store.save(JSON.stringify(set));
    await this.apply(set);
    return { kid, retired: kept.map((k) => k.kid) };
  }

  /** The key that signs new tokens. */
  signingKey(): { kid: string; privateKey: CryptoKey } {
    if (!this.active) throw new Error("No active signing key — call sync() first");
    return this.active;
  }

  /** Public keys to publish: the active one plus retired keys still inside their grace period. */
  publicKeys(now = new Date()): JWK[] {
    return this.keys
      .filter((k) => k.status === "active" || Date.parse(k.expiresAt) > now.getTime())
      .map((k) => ({ ...k.publicJwk }));
  }

  private async reload(): Promise<void> {
    const raw = await this.store.load();
    if (raw === null) {
      if (this.keys.length === 0) await this.rotateLoaded(new Date()); // first start: create and persist the first key
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(`Stored OIDC signing keys are not valid JSON: ${errorMessage(error)}`);
    }
    const result = keySetSchema.safeParse(parsed);
    if (!result.success) throw new Error(`Stored OIDC signing keys are malformed: ${result.error.message}`);
    await this.apply(result.data);
  }

  private async apply(set: SigningKeySet): Promise<void> {
    const actives = set.keys.filter((k) => k.status === "active");
    if (actives.length !== 1) throw new Error(`OIDC key set must have exactly one active key, found ${actives.length}`);
    const [current] = actives;
    if (this.active?.kid !== current.kid) {
      this.active = { kid: current.kid, privateKey: await importPKCS8(current.privateKeyPem, ALG) };
    }
    this.keys = set.keys;
  }
}

// ---------------------------------------------------------------- ID Tokens

export interface IdTokenInput {
  subject: string;
  audience: string;
  /** When the user actually authenticated (seconds precision in the token). */
  authTime: Date;
  /** Echoed from the authorization request; absent on refresh. */
  nonce?: string;
  /** The access token issued alongside, for at_hash. */
  accessToken: string;
  /** Extra claims allowed by the granted scopes (profile, email, ...). */
  claims: Record<string, string | boolean>;
}

export class IdTokenIssuer {
  constructor(
    private readonly settings: Pick<OidcSettings, "issuer" | "idTokenTtlSec">,
    private readonly keys: SigningKeyRing
  ) {}

  get issuer(): string {
    return this.settings.issuer;
  }

  /** GET /.well-known/jwks.json */
  jwks(): { keys: JWK[] } {
    return { keys: this.keys.publicKeys() };
  }

  async sign(input: IdTokenInput): Promise<string> {
    const { kid, privateKey } = this.keys.signingKey();
    return new SignJWT({
      ...input.claims,
      auth_time: Math.floor(input.authTime.getTime() / 1000),
      at_hash: IdTokenIssuer.atHash(input.accessToken),
      ...(input.nonce !== undefined ? { nonce: input.nonce } : {})
    })
      .setProtectedHeader({ alg: ALG, kid, typ: "JWT" })
      .setIssuer(this.settings.issuer)
      .setSubject(input.subject)
      .setAudience(input.audience)
      .setIssuedAt()
      .setExpirationTime(`${this.settings.idTokenTtlSec}s`)
      .sign(privateKey);
  }

  /** GET /.well-known/openid-configuration */
  discovery(apiScopes: readonly string[]) {
    const base = this.settings.issuer.replace(/\/$/, "");
    return {
      issuer: this.settings.issuer,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      userinfo_endpoint: `${base}/oauth/userinfo`,
      revocation_endpoint: `${base}/oauth/revoke`,
      jwks_uri: `${base}/.well-known/jwks.json`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: [ALG],
      scopes_supported: [...OIDC_SCOPES, ...apiScopes],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      claims_supported: [
        "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
        "name", "given_name", "family_name", "preferred_username", "locale", "email", "email_verified"
      ],
      claims_locales_supported: ["th", "en"]
    };
  }

  /** at_hash (OIDC Core §3.1.3.6): base64url of the left half of SHA-256(access_token). */
  private static atHash(accessToken: string): string {
    const digest = createHash("sha256").update(accessToken, "ascii").digest();
    return digest.subarray(0, digest.length / 2).toString("base64url");
  }
}
