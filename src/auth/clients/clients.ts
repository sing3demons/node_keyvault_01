// OAuth 2.0 client management: registration metadata (RFC 7591 §2), the management view
// (RFC 7591 §3.2.1 / RFC 7592), and client authentication at the token / revocation endpoints (RFC 6749 §2.3).

import { timingSafeEqual } from "node:crypto";
import { randomToken, sha256 } from "../shared/crypto.js";
import { HttpError } from "../shared/http.js";
import { MASTER_CLIENT_ID, type ClientGrantType, type EmailVerificationMethod, type OAuthClient, type TokenEndpointAuthMethod } from "./model.js";
import { OAuthError } from "./oauth.js";
import { isValidSender } from "../shared/mail.js";
import { DuplicateKeyError, type AuthRepository } from "./repository.js";
import type { ClientMetadataBody } from "./schemas.js";

/** Lifetimes used when the metadata does not set them, and their allowed ranges. */
export interface ClientLimits {
  defaults: { accessTokenTtlSec: number; refreshTokenTtlSec: number; idTokenTtlSec: number };
  /** ID Tokens must not outlive a retired signing key's stay in the JWKS (OIDC_RETIRED_KEY_GRACE_SEC). */
  maxIdTokenTtlSec: number;
  supportedScopes: ReadonlySet<string>;
  /** MAIL_FROM: sender for clients without their own mail_from. */
  defaultMailFrom: string;
}

/** Client as the management API shows it: RFC 7591 metadata names, plus this server's extensions. */
export interface ClientMetadata {
  client_id: string;
  client_name: string;
  client_id_issued_at: number;
  /** Only in the response that created / rotated it. */
  client_secret?: string;
  /** 0 = does not expire (RFC 7591 §3.2.1); present for confidential clients. */
  client_secret_expires_at?: 0;
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  redirect_uris: string[];
  grant_types: ClientGrantType[];
  response_types: ["code"];
  scope: string;
  client_uri?: string;
  initiate_login_uri?: string;
  /** Extensions (seconds / email method). */
  access_token_lifetime: number;
  refresh_token_lifetime: number;
  id_token_lifetime: number;
  email_verification: EmailVerificationMethod;
  /** Only when the client has its own sender (else the server's MAIL_FROM is used). */
  mail_from?: string;
  updated_at: number;
}

/** Credentials presented at the token endpoint, and how (RFC 6749 §2.3.1). */
export interface ClientCredentials {
  clientId?: string;
  clientSecret?: string;
  /** "basic" = Authorization header; "post" = client_secret in the form; "none" = client_id only. */
  via: "basic" | "post" | "none";
}

const epoch = (d: Date) => Math.floor(d.getTime() / 1000);
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function toClientMetadata(c: OAuthClient, secret?: string): ClientMetadata {
  return {
    client_id: c.id,
    client_name: c.name,
    client_id_issued_at: epoch(c.createdAt),
    ...(secret !== undefined ? { client_secret: secret } : {}),
    ...(c.tokenEndpointAuthMethod !== "none" ? { client_secret_expires_at: 0 as const } : {}),
    token_endpoint_auth_method: c.tokenEndpointAuthMethod,
    redirect_uris: c.redirectUris,
    grant_types: c.grantTypes,
    response_types: ["code"],
    scope: c.scope,
    ...(c.clientUri !== undefined ? { client_uri: c.clientUri } : {}),
    ...(c.initiateLoginUri !== undefined ? { initiate_login_uri: c.initiateLoginUri } : {}),
    access_token_lifetime: c.accessTokenTtlSec,
    refresh_token_lifetime: c.refreshTokenTtlSec,
    id_token_lifetime: c.idTokenTtlSec,
    email_verification: c.emailVerification,
    ...(c.mailFrom !== undefined ? { mail_from: c.mailFrom } : {}),
    updated_at: epoch(c.updatedAt)
  };
}

export class ClientService {
  constructor(
    private readonly repo: AuthRepository,
    private readonly limits: ClientLimits
  ) {}

  // ---------------------------------------------------------------- management (admin)

  async list(): Promise<ClientMetadata[]> {
    return (await this.repo.clients.list()).map((c) => toClientMetadata(c));
  }

  /** Sender used when a client has no mail_from (shown in the UI as the default). */
  get defaultMailFrom(): string {
    return this.limits.defaultMailFrom;
  }

  async get(id: string): Promise<ClientMetadata> {
    return toClientMetadata(await this.require(id));
  }

  /** RFC 7591 §3.1: register; confidential clients get a client_secret, shown only in this response. */
  async register(body: ClientMetadataBody): Promise<ClientMetadata> {
    const now = new Date();
    const fields = this.fromMetadata(body);
    const secret = fields.tokenEndpointAuthMethod !== "none" ? randomToken() : undefined;
    if (body.client_id === MASTER_CLIENT_ID) {
      throw new HttpError(400, `client_id "${MASTER_CLIENT_ID}" is reserved`, "invalid_client_metadata");
    }
    const client: OAuthClient = {
      id: body.client_id ?? randomToken(16),
      ...fields,
      ...(secret !== undefined ? { secretHash: sha256(secret) } : {}),
      createdAt: now,
      updatedAt: now
    };
    try {
      await this.repo.clients.create(client);
    } catch (error) {
      if (error instanceof DuplicateKeyError) throw new HttpError(409, `client_id "${client.id}" already exists`, "conflict");
      throw error;
    }
    return toClientMetadata(client, secret);
  }

  /**
   * RFC 7592 §2.2: the request carries the complete metadata (omitted optional fields are cleared).
   * Becoming confidential issues a secret; becoming public drops it.
   */
  async update(id: string, body: ClientMetadataBody): Promise<ClientMetadata> {
    if (body.client_id !== undefined && body.client_id !== id) {
      throw new HttpError(400, "client_id cannot be changed", "invalid_client_metadata");
    }
    const current = await this.require(id);
    const fields = this.fromMetadata(body);
    let secret: string | undefined;
    let secretHash = fields.tokenEndpointAuthMethod === "none" ? undefined : current.secretHash;
    if (fields.tokenEndpointAuthMethod !== "none" && !secretHash) {
      secret = randomToken();
      secretHash = sha256(secret);
    }
    const next: OAuthClient = {
      id,
      ...fields,
      ...(secretHash !== undefined ? { secretHash } : {}),
      createdAt: current.createdAt,
      updatedAt: new Date()
    };
    if (!(await this.repo.clients.update(next))) throw this.notFound(id);
    return toClientMetadata(next, secret);
  }

  /** New client_secret (the old one stops working at once). */
  async rotateSecret(id: string): Promise<ClientMetadata> {
    const current = await this.require(id);
    if (current.tokenEndpointAuthMethod === "none") {
      throw new HttpError(400, "Public clients have no secret", "invalid_client_metadata");
    }
    const secret = randomToken();
    const next = { ...current, secretHash: sha256(secret), updatedAt: new Date() };
    await this.repo.clients.update(next);
    return toClientMetadata(next, secret);
  }

  /** RFC 7592 §2.3: deleting a client also invalidates its tokens. */
  async delete(id: string, callerClientId: string | undefined): Promise<void> {
    if (id === callerClientId) {
      throw new HttpError(409, "Cannot delete the client you are signed in with", "conflict");
    }
    await this.require(id);
    await this.repo.tokens.revokeClient(id);
    await this.repo.clients.delete(id);
  }

  /** First start: create the built-in client (the React UI) unless it exists. */
  async seed(client: Omit<OAuthClient, "createdAt" | "updatedAt">): Promise<void> {
    if (await this.repo.clients.findById(client.id)) return;
    const now = new Date();
    try {
      await this.repo.clients.create({ ...client, createdAt: now, updatedAt: now });
      console.log(`Created OAuth client "${client.id}" (manage it in the UI: Clients, or /admin/clients)`);
    } catch (error) {
      if (!(error instanceof DuplicateKeyError)) throw error; // another instance seeded it first
    }
  }

  // ---------------------------------------------------------------- protocol

  /** /oauth/authorize: unknown client must not redirect anywhere (RFC 6749 §4.1.2.1). */
  async forAuthorization(clientId: string | undefined): Promise<OAuthClient> {
    const client = clientId ? await this.repo.clients.findById(clientId) : null;
    if (!client) throw new HttpError(400, "Unknown client_id", "invalid_client");
    return client;
  }

  find(clientId: string): Promise<OAuthClient | null> {
    return this.repo.clients.findById(clientId);
  }

  /**
   * RFC 6749 §2.3 / §3.2.1: the method must be the one the client registered. Public clients identify
   * themselves with client_id only (they must use PKCE, which the code exchange enforces).
   */
  async authenticate(cred: ClientCredentials): Promise<OAuthClient> {
    const fail = () =>
      new OAuthError("invalid_client", "Client authentication failed", 401);
    const client = cred.clientId ? await this.repo.clients.findById(cred.clientId) : null;
    if (!client) throw fail();
    const expected = { none: "none", client_secret_basic: "basic", client_secret_post: "post" }[client.tokenEndpointAuthMethod];
    if (cred.via !== expected) throw fail();
    if (client.tokenEndpointAuthMethod !== "none") {
      const given = Buffer.from(sha256(cred.clientSecret ?? ""));
      const stored = Buffer.from(client.secretHash ?? "");
      if (given.length !== stored.length || !timingSafeEqual(given, stored)) throw fail();
    }
    return client;
  }

  // ---------------------------------------------------------------- helpers

  private async require(id: string): Promise<OAuthClient> {
    const client = await this.repo.clients.findById(id);
    if (!client) throw this.notFound(id);
    return client;
  }

  private notFound(id: string): HttpError {
    return new HttpError(404, `Client "${id}" not found`);
  }

  /** Validated metadata -> stored fields (RFC 7591 defaults where omitted). */
  private fromMetadata(m: ClientMetadataBody): Omit<OAuthClient, "id" | "secretHash" | "createdAt" | "updatedAt"> {
    const invalid = (msg: string) => new HttpError(400, msg, "invalid_client_metadata");
    for (const uri of m.redirect_uris) this.assertRedirectUri(uri);
    if (m.initiate_login_uri !== undefined) this.assertWebUri(m.initiate_login_uri, "initiate_login_uri");
    if (m.client_uri !== undefined) this.assertWebUri(m.client_uri, "client_uri");
    const mailFrom = m.mail_from?.trim() || undefined;
    if (mailFrom !== undefined && !isValidSender(mailFrom)) {
      throw invalid('mail_from must be "Name <address@domain>" or "address@domain"');
    }

    // RFC 7591 §2: grant_types defaults to authorization_code; refresh only makes sense alongside it
    const grantTypes = [...new Set<ClientGrantType>(m.grant_types ?? ["authorization_code"])];
    const authMethod = m.token_endpoint_auth_method ?? "client_secret_basic";
    if (grantTypes.includes("refresh_token") && !grantTypes.includes("authorization_code")) {
      throw invalid("refresh_token needs authorization_code (client_credentials gets no refresh token)");
    }
    // RFC 6749 §4.4: only confidential clients
    if (grantTypes.includes("client_credentials") && authMethod === "none") {
      throw invalid("client_credentials needs a confidential client (client_secret_basic or client_secret_post)");
    }
    // redirect-based grant => at least one redirect_uri (RFC 7591 §2)
    if (grantTypes.includes("authorization_code") && m.redirect_uris.length === 0) {
      throw new HttpError(400, "at least one redirect_uri is required for authorization_code", "invalid_redirect_uri");
    }
    if (m.response_types && m.response_types.some((t) => t !== "code")) throw invalid('response_types must be ["code"]');

    const scopes = [...new Set((m.scope ?? "openid profile email").split(" ").filter(Boolean))];
    const unknown = scopes.filter((s) => !this.limits.supportedScopes.has(s));
    if (scopes.length === 0 || unknown.length) throw invalid(`Unsupported scope: ${unknown.join(" ") || "(empty)"}`);

    const d = this.limits.defaults;
    const idTtl = m.id_token_lifetime ?? Math.min(d.idTokenTtlSec, this.limits.maxIdTokenTtlSec);
    if (idTtl > this.limits.maxIdTokenTtlSec) {
      throw invalid(`id_token_lifetime must be at most ${this.limits.maxIdTokenTtlSec}s (OIDC_RETIRED_KEY_GRACE_SEC)`);
    }
    return {
      name: m.client_name,
      // RFC 7591 §2: the default is client_secret_basic
      tokenEndpointAuthMethod: authMethod,
      redirectUris: [...new Set(m.redirect_uris)],
      grantTypes,
      scope: scopes.sort().join(" "),
      ...(m.client_uri !== undefined ? { clientUri: m.client_uri } : {}),
      ...(m.initiate_login_uri !== undefined ? { initiateLoginUri: m.initiate_login_uri } : {}),
      accessTokenTtlSec: m.access_token_lifetime ?? d.accessTokenTtlSec,
      refreshTokenTtlSec: m.refresh_token_lifetime ?? d.refreshTokenTtlSec,
      idTokenTtlSec: idTtl,
      emailVerification: m.email_verification ?? "code",
      ...(mailFrom !== undefined ? { mailFrom } : {})
    };
  }

  /**
   * RFC 6749 §3.1.2 + RFC 8252: absolute, no fragment; https, http only on loopback, or a private-use
   * scheme in reverse-domain form for native apps (com.example.app:/callback).
   */
  private assertRedirectUri(uri: string): void {
    const bad = (why: string) => new HttpError(400, `redirect_uri "${uri}" ${why}`, "invalid_redirect_uri");
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      throw bad("is not an absolute URI");
    }
    if (url.hash || uri.includes("#")) throw bad("must not contain a fragment");
    if (url.protocol === "https:") return;
    if (url.protocol === "http:") {
      if (LOOPBACK.has(url.hostname)) return;
      throw bad("must use https (http is allowed only for localhost)");
    }
    if (/^[a-z][a-z0-9+-]*\.[a-z0-9+.-]+:$/i.test(url.protocol)) return; // private-use scheme
    throw bad("must use https, http on localhost, or a reverse-domain private-use scheme");
  }

  private assertWebUri(uri: string, field: string): void {
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      throw new HttpError(400, `${field} is not an absolute URI`, "invalid_client_metadata");
    }
    const ok = url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname));
    if (!ok || url.hash) {
      throw new HttpError(400, `${field} must be https (or http on localhost), without a fragment`, "invalid_client_metadata");
    }
  }
}
