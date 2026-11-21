import argon2 from "argon2";
import { ObjectId } from "mongodb";
import { randomToken, sha256, verifyPkceS256 } from "./crypto.js";
import { HttpError, OAuthError } from "./errors.js";
import type { AuthStore, UserDoc } from "./store.js";

export interface OAuthSettings {
  clientId: string;
  redirectUris: string[];
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
}

export interface AuthorizeParams {
  responseType?: string;
  clientId?: string;
  redirectUri?: string;
  state?: string;
  scope?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
}

export interface AuthenticatedUser {
  id: string;
  username: string;
  scope: string;
  clientId: string;
}

const SUPPORTED_SCOPES = new Set(["secrets"]);
const DEFAULT_SCOPE = "secrets";
const AUTH_REQUEST_TTL_MS = 10 * 60_000;
const AUTH_CODE_TTL_MS = 60_000;

const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;
const ARGON2_OPTIONS = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

const later = (ms: number) => new Date(Date.now() + ms);

export class AuthService {
  private dummyHash?: Promise<string>;

  constructor(
    private readonly store: AuthStore,
    private readonly oauth: OAuthSettings
  ) {}

  // ---------------------------------------------------------------- users

  async register(rawUsername: unknown, password: unknown): Promise<{ id: string; username: string }> {
    const username = typeof rawUsername === "string" ? rawUsername.trim().toLowerCase() : "";
    if (!USERNAME_RE.test(username)) {
      throw new HttpError(400, "Username must be 3-32 chars: a-z, 0-9, _ . -");
    }
    if (typeof password !== "string" || password.length < 8 || password.length > 256) {
      throw new HttpError(400, "Password must be 8-256 characters");
    }
    const passwordHash = await argon2.hash(password, ARGON2_OPTIONS);
    const doc: UserDoc = { _id: new ObjectId(), username, passwordHash, createdAt: new Date() };
    try {
      await this.store.users.insertOne(doc);
    } catch (error) {
      if ((error as { code?: number }).code === 11000) {
        throw new HttpError(409, "Username already taken");
      }
      throw error;
    }
    return { id: doc._id.toHexString(), username };
  }

  async verifyPassword(rawUsername: unknown, password: unknown): Promise<UserDoc> {
    const username = typeof rawUsername === "string" ? rawUsername.trim().toLowerCase() : "";
    const pw = typeof password === "string" ? password : "";
    const user = username ? await this.store.users.findOne({ username }) : null;
    // Always run argon2 so response time does not reveal whether the user exists
    const hash = user?.passwordHash ?? (await this.getDummyHash());
    const ok = await argon2.verify(hash, pw).catch(() => false);
    if (!user || !ok) {
      throw new HttpError(401, "Invalid username or password");
    }
    if (argon2.needsRehash(user.passwordHash, ARGON2_OPTIONS)) {
      const passwordHash = await argon2.hash(pw, ARGON2_OPTIONS);
      await this.store.users.updateOne({ _id: user._id }, { $set: { passwordHash } });
    }
    return user;
  }

  async getUser(id: string | ObjectId): Promise<UserDoc | null> {
    const _id = typeof id === "string" ? (ObjectId.isValid(id) ? new ObjectId(id) : null) : id;
    return _id ? this.store.users.findOne({ _id }) : null;
  }

  private getDummyHash(): Promise<string> {
    this.dummyHash ??= argon2.hash(randomToken(), ARGON2_OPTIONS);
    return this.dummyHash;
  }

  // ---------------------------------------------------------------- /oauth/authorize

  /**
   * Validates an authorization request. Errors about client/redirect_uri are thrown as HttpError
   * (must NOT redirect); everything else is returned as a redirect to the client with `error`.
   */
  async createAuthRequest(p: AuthorizeParams): Promise<{ requestId: string } | { redirect: string }> {
    if (p.clientId !== this.oauth.clientId) {
      throw new HttpError(400, "Unknown client_id");
    }
    if (!p.redirectUri || !this.oauth.redirectUris.includes(p.redirectUri)) {
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
    const scope = this.normalizeScope(p.scope);
    if (!scope) {
      return fail("invalid_scope", "Unsupported scope");
    }
    const requestId = randomToken(24);
    await this.store.authRequests.insertOne({
      _id: requestId,
      clientId: p.clientId,
      redirectUri: p.redirectUri,
      state: p.state,
      scope,
      codeChallenge: p.codeChallenge,
      expiresAt: later(AUTH_REQUEST_TTL_MS)
    });
    return { requestId };
  }

  /** Throws if the pending authorization request does not exist / expired (does not consume it). */
  async assertAuthRequest(requestId: unknown): Promise<void> {
    if (typeof requestId !== "string" || !requestId) {
      throw new HttpError(400, "request_id is required");
    }
    const req = await this.store.authRequests.findOne({ _id: requestId, expiresAt: { $gt: new Date() } });
    if (!req) {
      throw new HttpError(400, "Authorization request expired or not found — please start sign-in again");
    }
  }

  /** User authenticated: consume the authorization request and issue a one-time code. */
  async completeAuthRequest(requestId: string, userId: ObjectId): Promise<{ redirect: string }> {
    const req = await this.store.authRequests.findOneAndDelete({ _id: requestId, expiresAt: { $gt: new Date() } });
    if (!req) {
      throw new HttpError(400, "Authorization request expired or not found — please start sign-in again");
    }
    const code = randomToken();
    await this.store.authCodes.insertOne({
      _id: sha256(code),
      userId,
      clientId: req.clientId,
      redirectUri: req.redirectUri,
      scope: req.scope,
      codeChallenge: req.codeChallenge,
      familyId: randomToken(16),
      used: false,
      expiresAt: later(AUTH_CODE_TTL_MS)
    });
    return { redirect: this.buildRedirect(req.redirectUri, { code, state: req.state }) };
  }

  // ---------------------------------------------------------------- /oauth/token

  async exchangeCode(p: {
    code?: string;
    redirectUri?: string;
    clientId?: string;
    codeVerifier?: string;
  }): Promise<TokenResponse> {
    if (!p.code || !p.redirectUri || !p.clientId || !p.codeVerifier) {
      throw new OAuthError("invalid_request", "code, redirect_uri, client_id and code_verifier are required");
    }
    if (p.clientId !== this.oauth.clientId) {
      throw new OAuthError("invalid_client", "Unknown client", 401);
    }
    // Atomically mark as used so a code can only be redeemed once
    const codeDoc = await this.store.authCodes.findOneAndUpdate(
      { _id: sha256(p.code), used: false },
      { $set: { used: true } }
    );
    if (!codeDoc) {
      const replayed = await this.store.authCodes.findOne({ _id: sha256(p.code) });
      if (replayed) {
        // RFC 6749 §4.1.2: code reuse => revoke tokens previously issued from it
        await this.revokeFamily(replayed.familyId);
      }
      throw new OAuthError("invalid_grant", "Authorization code is invalid, expired or already used");
    }
    if (codeDoc.expiresAt <= new Date()) {
      throw new OAuthError("invalid_grant", "Authorization code is invalid, expired or already used");
    }
    if (codeDoc.clientId !== p.clientId || codeDoc.redirectUri !== p.redirectUri) {
      throw new OAuthError("invalid_grant", "client_id or redirect_uri does not match the authorization request");
    }
    if (!verifyPkceS256(p.codeVerifier, codeDoc.codeChallenge)) {
      throw new OAuthError("invalid_grant", "PKCE verification failed");
    }
    return this.issueTokens(codeDoc.userId, codeDoc.clientId, codeDoc.scope, codeDoc.familyId);
  }

  async refresh(p: { refreshToken?: string; clientId?: string; scope?: string }): Promise<TokenResponse> {
    if (!p.refreshToken || !p.clientId) {
      throw new OAuthError("invalid_request", "refresh_token and client_id are required");
    }
    if (p.clientId !== this.oauth.clientId) {
      throw new OAuthError("invalid_client", "Unknown client", 401);
    }
    const tokenHash = sha256(p.refreshToken);
    // Rotation: consume the old refresh token atomically
    const current = await this.store.refreshTokens.findOneAndUpdate(
      { _id: tokenHash, revoked: false },
      { $set: { revoked: true } }
    );
    if (!current) {
      const reused = await this.store.refreshTokens.findOne({ _id: tokenHash });
      if (reused) {
        // A rotated-out refresh token was presented again => assume theft, kill the whole family
        await this.revokeFamily(reused.familyId);
      }
      throw new OAuthError("invalid_grant", "Refresh token is invalid or revoked");
    }
    if (current.expiresAt <= new Date() || current.clientId !== p.clientId) {
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
    return this.issueTokens(current.userId, current.clientId, scope, current.familyId);
  }

  /** RFC 7009 — revoking either token type ends the whole session (family). */
  async revoke(token: string | undefined): Promise<void> {
    if (!token) return;
    const hash = sha256(token);
    const doc =
      (await this.store.refreshTokens.findOne({ _id: hash })) ?? (await this.store.accessTokens.findOne({ _id: hash }));
    if (doc) {
      await this.revokeFamily(doc.familyId);
    }
  }

  // ---------------------------------------------------------------- bearer validation

  async authenticate(accessToken: string): Promise<AuthenticatedUser | null> {
    const token = await this.store.accessTokens.findOne({ _id: sha256(accessToken), expiresAt: { $gt: new Date() } });
    if (!token) return null;
    const user = await this.store.users.findOne({ _id: token.userId }, { projection: { username: 1 } });
    if (!user) return null;
    return { id: user._id.toHexString(), username: user.username, scope: token.scope, clientId: token.clientId };
  }

  // ---------------------------------------------------------------- helpers

  private async issueTokens(userId: ObjectId, clientId: string, scope: string, familyId: string): Promise<TokenResponse> {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const { accessTokenTtlSec, refreshTokenTtlSec } = this.oauth;
    await Promise.all([
      this.store.accessTokens.insertOne({
        _id: sha256(accessToken),
        userId,
        clientId,
        scope,
        familyId,
        expiresAt: later(accessTokenTtlSec * 1000)
      }),
      this.store.refreshTokens.insertOne({
        _id: sha256(refreshToken),
        userId,
        clientId,
        scope,
        familyId,
        revoked: false,
        expiresAt: later(refreshTokenTtlSec * 1000)
      })
    ]);
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: accessTokenTtlSec,
      refresh_token: refreshToken,
      scope
    };
  }

  private async revokeFamily(familyId: string): Promise<void> {
    await Promise.all([
      this.store.refreshTokens.updateMany({ familyId }, { $set: { revoked: true } }),
      this.store.accessTokens.deleteMany({ familyId })
    ]);
  }

  private normalizeScope(scope: string | undefined): string | null {
    const parts = (scope ?? DEFAULT_SCOPE).split(" ").filter(Boolean);
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
