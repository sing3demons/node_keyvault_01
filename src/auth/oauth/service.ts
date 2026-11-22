// OAuth 2.0 / OpenID Connect authorization server: authorization requests and codes, the token endpoint
// (authorization_code, refresh_token, client_credentials), revocation, introspection, UserInfo, and
// resolving Bearer tokens for the API.

import { randomToken, sha256 } from "../../shared/crypto.js";
import { HttpError } from "../../shared/http.js";
import type { AuthenticatedUser, TokenAuthenticator } from "../../shared/middleware.js";
import { expiresIn } from "../../shared/util.js";
import type { ClientCredentials, ClientService } from "../clients/clients.js";
import type { DeviceContext, DeviceService } from "../devices/devices.js";
import { displayProfile, MASTER_CLIENT_ID, type AuthRequest, type OAuthClient, type SignInMethod, type User } from "../model.js";
import type { AuthRepository } from "../repository.js";
import { OIDC_SCOPES, type IdTokenIssuer } from "./oidc.js";
import { OAuthError, verifyPkceS256 } from "./protocol.js";

export interface AuthorizeParams {
  responseType?: string;
  clientId?: string;
  redirectUri?: string;
  state?: string;
  scope?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  /** Only for clients registered with the refresh_token grant. */
  refresh_token?: string;
  scope: string;
  /** Present when the grant includes the "openid" scope. */
  id_token?: string;
}

/** How a sign-in was completed, recorded against the device it came from. */
export interface SignIn {
  device: DeviceContext;
  method: SignInMethod;
}

/** OpenID Connect UserInfo claims (OIDC Core §5.1), with per-language profiles as "claim#lang" (§5.2). */
export type UserInfoClaims = Record<string, string | boolean>;

/** Scopes protecting this API (as opposed to the OIDC identity scopes). */
export const API_SCOPES = ["secrets"] as const;
export const SUPPORTED_SCOPES: ReadonlySet<string> = new Set<string>([...OIDC_SCOPES, ...API_SCOPES]);
const AUTH_REQUEST_TTL_MS = 10 * 60_000;
const AUTH_CODE_TTL_MS = 60_000;

const expired = () => new HttpError(400, "Authorization request expired or not found — please start sign-in again");

export class OAuthService implements TokenAuthenticator {
  constructor(
    private readonly repo: AuthRepository,
    private readonly clients: ClientService,
    private readonly idTokens: IdTokenIssuer,
    private readonly devices: DeviceService
  ) {}

  get issuer(): string {
    return this.idTokens.issuer;
  }

  // ---------------------------------------------------------------- /oauth/authorize

  /**
   * Validates an authorization request. Errors about client/redirect_uri are thrown as HttpError
   * (must NOT redirect); everything else is returned as a redirect to the client with `error`.
   */
  async createAuthRequest(p: AuthorizeParams): Promise<{ requestId: string } | { redirect: string }> {
    const client = await this.clients.forAuthorization(p.clientId);
    // exact match against the registered list (RFC 6749 §3.1.2.3)
    if (!p.redirectUri || !client.redirectUris.includes(p.redirectUri)) {
      throw new HttpError(400, "Invalid redirect_uri");
    }
    const fail = (error: string, description: string) => ({
      redirect: this.buildRedirect(p.redirectUri!, { error, error_description: description, state: p.state })
    });
    if (p.responseType !== "code") {
      return fail("unsupported_response_type", "Only response_type=code is supported");
    }
    if (!p.codeChallenge || p.codeChallengeMethod !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(p.codeChallenge)) {
      return fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
    }
    // no scope requested => the client's registered scope (RFC 6749 §3.3)
    const scope = this.normalizeScope(p.scope ?? client.scope);
    if (!scope || !this.within(scope, client.scope)) {
      return fail("invalid_scope", "Requested scope is not allowed for this client");
    }
    const requestId = randomToken(24);
    await this.repo.authRequests.create({
      id: requestId,
      clientId: client.id,
      redirectUri: p.redirectUri,
      state: p.state,
      scope,
      codeChallenge: p.codeChallenge,
      ...(p.nonce !== undefined ? { nonce: p.nonce } : {}),
      expiresAt: expiresIn(AUTH_REQUEST_TTL_MS)
    });
    return { requestId };
  }

  /** The pending authorization request (not consumed); throws if it does not exist or expired. */
  async requireAuthRequest(requestId: string): Promise<AuthRequest> {
    const req = await this.repo.authRequests.findActive(requestId, new Date());
    if (!req) throw expired();
    return req;
  }

  /** null when missing / expired (callers that have another way forward). */
  findAuthRequest(requestId: string): Promise<AuthRequest | null> {
    return this.repo.authRequests.findActive(requestId, new Date());
  }

  /** The client an authorization request is for (it may have been deleted since). */
  async clientOf(req: AuthRequest): Promise<OAuthClient> {
    const client = await this.clients.find(req.clientId);
    if (!client) throw new HttpError(400, "This app is no longer registered", "invalid_client");
    return client;
  }

  /** User authenticated: consume the authorization request, record the device and issue a one-time code. */
  async completeAuthRequest(requestId: string, userId: string, signIn: SignIn): Promise<{ redirect: string }> {
    const req = await this.repo.authRequests.consumeActive(requestId, new Date());
    if (!req) throw expired();
    const deviceId = await this.devices.recordSignIn(userId, signIn.device, signIn.method);
    const code = randomToken();
    await this.repo.authCodes.create({
      id: sha256(code),
      userId,
      clientId: req.clientId,
      redirectUri: req.redirectUri,
      scope: req.scope,
      codeChallenge: req.codeChallenge,
      familyId: randomToken(16),
      ...(req.nonce !== undefined ? { nonce: req.nonce } : {}),
      authTime: new Date(),
      deviceId,
      used: false,
      expiresAt: expiresIn(AUTH_CODE_TTL_MS)
    });
    return { redirect: this.buildRedirect(req.redirectUri, { code, state: req.state }) };
  }

  // ---------------------------------------------------------------- /oauth/token

  async exchangeCode(p: {
    code: string;
    redirectUri: string;
    client: ClientCredentials;
    codeVerifier: string;
  }): Promise<TokenResponse> {
    const client = await this.clients.authenticate(p.client);
    // Atomically mark as used so a code can only be redeemed once
    const codeDoc = await this.repo.authCodes.redeem(sha256(p.code));
    if (!codeDoc) {
      const replayed = await this.repo.authCodes.find(sha256(p.code));
      if (replayed) {
        // RFC 6749 §4.1.2: code reuse => revoke tokens previously issued from it
        await this.revokeFamily(replayed.familyId);
      }
      throw new OAuthError("invalid_grant", "Authorization code is invalid, expired or already used");
    }
    if (codeDoc.expiresAt <= new Date()) {
      throw new OAuthError("invalid_grant", "Authorization code is invalid, expired or already used");
    }
    if (codeDoc.clientId !== client.id || codeDoc.redirectUri !== p.redirectUri) {
      throw new OAuthError("invalid_grant", "client_id or redirect_uri does not match the authorization request");
    }
    if (!verifyPkceS256(p.codeVerifier, codeDoc.codeChallenge)) {
      throw new OAuthError("invalid_grant", "PKCE verification failed");
    }
    return this.issueTokens(codeDoc.userId, client, codeDoc.scope, codeDoc.familyId, {
      authTime: codeDoc.authTime ?? new Date(),
      nonce: codeDoc.nonce,
      deviceId: codeDoc.deviceId
    });
  }

  async refresh(p: { refreshToken: string; client: ClientCredentials; scope?: string }): Promise<TokenResponse> {
    const client = await this.clients.authenticate(p.client);
    if (!client.grantTypes.includes("refresh_token")) {
      throw new OAuthError("unauthorized_client", "This client may not use the refresh_token grant");
    }
    const tokenHash = sha256(p.refreshToken);
    // Rotation: consume the old refresh token atomically
    const current = await this.repo.tokens.rotateRefresh(tokenHash);
    if (!current) {
      const reused = await this.repo.tokens.findRefresh(tokenHash);
      if (reused) {
        // A rotated-out refresh token was presented again => assume theft, kill the whole family
        await this.revokeFamily(reused.familyId);
      }
      throw new OAuthError("invalid_grant", "Refresh token is invalid or revoked");
    }
    if (current.expiresAt <= new Date() || current.clientId !== client.id) {
      throw new OAuthError("invalid_grant", "Refresh token is invalid or expired");
    }
    let scope = current.scope;
    if (p.scope) {
      const requested = this.normalizeScope(p.scope);
      const granted = new Set(current.scope.split(" "));
      if (!requested || !requested.split(" ").every((s) => granted.has(s))) {
        throw new OAuthError("invalid_scope", "Requested scope exceeds the original grant");
      }
      scope = requested;
    }
    if (current.deviceId) {
      await this.devices.touch(current.deviceId).catch((e) => console.error("device touch failed", e));
    }
    // OIDC Core §12.2: refreshed ID Tokens keep auth_time; nonce is not repeated
    return this.issueTokens(current.userId, client, scope, current.familyId, {
      authTime: current.authTime ?? new Date(),
      deviceId: current.deviceId
    });
  }

  /**
   * RFC 6749 §4.4 client_credentials: a token for the client itself (no user). Only API scopes — the OIDC
   * identity scopes describe a user — and no refresh token (§4.4.3) or ID Token.
   */
  async clientCredentials(p: { client: ClientCredentials; scope?: string }): Promise<TokenResponse> {
    const client = await this.clients.authenticate(p.client);
    if (!client.grantTypes.includes("client_credentials") || client.tokenEndpointAuthMethod === "none") {
      throw new OAuthError("unauthorized_client", "This client may not use the client_credentials grant");
    }
    const apiScopes = client.scope.split(" ").filter((s) => !OIDC_SCOPES.includes(s as never));
    const scope = p.scope !== undefined ? this.normalizeScope(p.scope) : apiScopes.sort().join(" ");
    if (!scope || !this.within(scope, apiScopes.join(" "))) {
      throw new OAuthError("invalid_scope", `Allowed scopes for client_credentials: ${apiScopes.join(" ") || "(none)"}`);
    }
    const accessToken = randomToken();
    await this.repo.tokens.createPair(
      {
        id: sha256(accessToken),
        clientId: client.id,
        scope,
        familyId: randomToken(16),
        expiresAt: expiresIn(client.accessTokenTtlSec * 1000)
      },
      null
    );
    return { access_token: accessToken, token_type: "Bearer", expires_in: client.accessTokenTtlSec, scope };
  }

  // ---------------------------------------------------------------- /oauth/introspect, /oauth/revoke

  /**
   * RFC 7662 token introspection, for resource servers (confidential clients) holding an opaque token.
   * Anything unknown, expired or revoked is just { active: false }.
   */
  async introspect(token: string | undefined, credentials: ClientCredentials): Promise<Record<string, unknown>> {
    const caller = await this.clients.authenticate(credentials);
    if (caller.tokenEndpointAuthMethod === "none") {
      throw new OAuthError("invalid_client", "Public clients cannot introspect tokens", 401);
    }
    if (!token) return { active: false };
    const hash = sha256(token);
    const now = new Date();
    const access = await this.repo.tokens.findActiveAccess(hash, now);
    const refresh = access ? null : await this.repo.tokens.findRefresh(hash);
    const doc = access ?? (refresh && !refresh.revoked && refresh.expiresAt > now ? refresh : null);
    // master sessions are internal to this server
    if (!doc || doc.clientId === MASTER_CLIENT_ID) return { active: false };
    const user = doc.userId ? await this.repo.users.findById(doc.userId) : null;
    if (doc.userId && !user) return { active: false };
    return {
      active: true,
      scope: doc.scope,
      client_id: doc.clientId,
      token_type: access ? "Bearer" : "refresh_token",
      exp: Math.floor(doc.expiresAt.getTime() / 1000),
      iss: this.idTokens.issuer,
      // user tokens: who; client_credentials tokens: the client itself (RFC 7662 §2.2 "sub")
      sub: user ? user.id : doc.clientId,
      ...(user ? { username: user.username } : {})
    };
  }

  /**
   * RFC 7009 — the client authenticates as at the token endpoint and may revoke only its own tokens
   * (others are ignored, still 200). Revoking either token type ends the whole session (family).
   */
  async revoke(token: string | undefined, credentials: ClientCredentials): Promise<void> {
    const client = await this.clients.authenticate(credentials);
    if (!token) return;
    const hash = sha256(token);
    const doc = (await this.repo.tokens.findRefresh(hash)) ?? (await this.repo.tokens.findAccess(hash));
    if (doc && doc.clientId === client.id) {
      await this.revokeFamily(doc.familyId);
    }
  }

  // ---------------------------------------------------------------- /oauth/userinfo, Bearer tokens

  /** Claims for /oauth/userinfo: `sub` plus whatever the token's scopes allow. */
  async userInfo(userId: string, scope: string): Promise<UserInfoClaims> {
    const user = await this.requireUser(userId);
    return { sub: user.id, ...this.scopedClaims(user, scope) };
  }

  async authenticate(accessToken: string): Promise<AuthenticatedUser | null> {
    const token = await this.repo.tokens.findActiveAccess(sha256(accessToken), new Date());
    if (!token) return null;
    if (!token.userId) {
      // valid, but not a user's (client_credentials, master session): these endpoints act for a user
      throw new HttpError(403, "This endpoint needs a user's access token", "insufficient_scope");
    }
    const user = await this.repo.users.findById(token.userId);
    if (!user) return null;
    return {
      id: user.id,
      username: user.username,
      scope: token.scope,
      clientId: token.clientId,
      roles: user.roles,
      ...(token.deviceId !== undefined ? { deviceId: token.deviceId } : {}),
      familyId: token.familyId
    };
  }

  // ---------------------------------------------------------------- helpers

  /** OIDC Core §5.4: "profile" -> name claims (per language as claim#lang, §5.2), "email" -> email. */
  private scopedClaims(user: User, scope: string): UserInfoClaims {
    const granted = new Set(scope.split(" "));
    const claims: UserInfoClaims = {};
    if (granted.has("profile")) {
      claims.preferred_username = user.username;
      const shown = displayProfile(user);
      if (shown) {
        claims.name = `${shown.firstName} ${shown.lastName}`;
        claims.given_name = shown.firstName;
        claims.family_name = shown.lastName;
        claims.locale = shown.lang;
      }
      for (const p of user.profiles) {
        claims[`name#${p.lang}`] = `${p.firstName} ${p.lastName}`;
        claims[`given_name#${p.lang}`] = p.firstName;
        claims[`family_name#${p.lang}`] = p.lastName;
      }
    }
    if (granted.has("email") && user.email) {
      claims.email = user.email;
      claims.email_verified = !!user.emailVerifiedAt;
    }
    return claims;
  }

  /** Lifetimes come from the client; a refresh token only for clients with the refresh_token grant. */
  private async issueTokens(
    userId: string,
    client: OAuthClient,
    scope: string,
    familyId: string,
    session: { authTime: Date; nonce?: string; deviceId?: string }
  ): Promise<TokenResponse> {
    const clientId = client.id;
    const accessToken = randomToken();
    const refreshToken = client.grantTypes.includes("refresh_token") ? randomToken() : undefined;
    const { accessTokenTtlSec, refreshTokenTtlSec } = client;
    const device = session.deviceId !== undefined ? { deviceId: session.deviceId } : {};
    await this.repo.tokens.createPair(
      { id: sha256(accessToken), userId, clientId, scope, familyId, ...device, expiresAt: expiresIn(accessTokenTtlSec * 1000) },
      refreshToken
        ? {
            id: sha256(refreshToken),
            userId,
            clientId,
            scope,
            familyId,
            ...device,
            revoked: false,
            authTime: session.authTime,
            expiresAt: expiresIn(refreshTokenTtlSec * 1000)
          }
        : null
    );
    const response: TokenResponse = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: accessTokenTtlSec,
      ...(refreshToken ? { refresh_token: refreshToken } : {}),
      scope
    };
    if (scope.split(" ").includes("openid")) {
      const user = await this.requireUser(userId);
      response.id_token = await this.idTokens.sign({
        subject: user.id,
        audience: clientId,
        authTime: session.authTime,
        nonce: session.nonce,
        accessToken,
        ttlSec: client.idTokenTtlSec,
        claims: this.scopedClaims(user, scope)
      });
    }
    return response;
  }

  private async requireUser(userId: string): Promise<User> {
    const user = await this.repo.users.findById(userId);
    if (!user) throw new HttpError(404, "User not found");
    return user;
  }

  private revokeFamily(familyId: string): Promise<void> {
    return this.repo.tokens.revokeFamily(familyId);
  }

  /** Every scope in `scope` is also in `allowed`. */
  private within(scope: string, allowed: string): boolean {
    const set = new Set(allowed.split(" "));
    return scope.split(" ").every((s) => set.has(s));
  }

  private normalizeScope(scope: string): string | null {
    const parts = scope.split(" ").filter(Boolean);
    if (parts.length === 0 || !parts.every((s) => SUPPORTED_SCOPES.has(s))) return null;
    return [...new Set(parts)].sort().join(" ");
  }

  private buildRedirect(redirectUri: string, params: Record<string, string | undefined>): string {
    const url = new URL(redirectUri);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined) url.searchParams.set(key, value);
    }
    return url.toString();
  }
}
