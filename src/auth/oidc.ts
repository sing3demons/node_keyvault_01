// OpenID Connect on top of the OAuth server: signed ID Tokens (OIDC Core §2), the public keys
// to verify them (JWKS) and the discovery document (OIDC Discovery §3).

import { createHash } from "node:crypto";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importPKCS8, SignJWT, type CryptoKey, type JWK } from "jose";

export interface OidcSettings {
  /** Issuer identifier: an https URL in production, e.g. https://auth.example.com */
  issuer: string;
  /** PKCS#8 PEM RSA private key. Without it a key is generated per process (dev only). */
  privateKeyPem?: string;
  idTokenTtlSec: number;
}

/** Scopes defined by OIDC Core §5.4 that this server supports, plus the API scope. */
export const OIDC_SCOPES = ["openid", "profile", "email"] as const;

const ALG = "RS256"; // the one algorithm OIDC requires every provider to support
const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth"] as const;

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
  private constructor(
    private readonly settings: OidcSettings,
    private readonly privateKey: CryptoKey,
    private readonly publicJwk: JWK
  ) {}

  static async create(settings: OidcSettings): Promise<IdTokenIssuer> {
    let privateKey: CryptoKey;
    if (settings.privateKeyPem) {
      privateKey = await importPKCS8(settings.privateKeyPem, ALG, { extractable: true });
    } else {
      console.warn("OIDC_PRIVATE_KEY not set: using a temporary signing key; ID Tokens become unverifiable after restart");
      ({ privateKey } = await generateKeyPair(ALG, { extractable: true, modulusLength: 2048 }));
    }
    const jwk = await exportJWK(privateKey);
    for (const field of PRIVATE_JWK_FIELDS) delete jwk[field];
    const publicJwk: JWK = { ...jwk, kid: await calculateJwkThumbprint(jwk), alg: ALG, use: "sig" };
    return new IdTokenIssuer(settings, privateKey, publicJwk);
  }

  get issuer(): string {
    return this.settings.issuer;
  }

  /** GET /.well-known/jwks.json */
  jwks(): { keys: JWK[] } {
    return { keys: [this.publicJwk] };
  }

  async sign(input: IdTokenInput): Promise<string> {
    return new SignJWT({
      ...input.claims,
      auth_time: Math.floor(input.authTime.getTime() / 1000),
      at_hash: IdTokenIssuer.atHash(input.accessToken),
      ...(input.nonce !== undefined ? { nonce: input.nonce } : {})
    })
      .setProtectedHeader({ alg: ALG, kid: this.publicJwk.kid, typ: "JWT" })
      .setIssuer(this.settings.issuer)
      .setSubject(input.subject)
      .setAudience(input.audience)
      .setIssuedAt()
      .setExpirationTime(`${this.settings.idTokenTtlSec}s`)
      .sign(this.privateKey);
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
