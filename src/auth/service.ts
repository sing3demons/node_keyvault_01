import argon2 from "argon2";
import { randomUUID } from "node:crypto";
import { randomToken, sha256, verifyPkceS256 } from "./crypto.js";
import { HttpError, OAuthError } from "./errors.js";
import { DuplicateKeyError, type AuthRepository, type User } from "./repository.js";

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
    private readonly repo: AuthRepository,
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
    const user: User = { id: randomUUID(), username, passwordHash, createdAt: new Date() };
    try {
      await this.repo.users.create(user);
    } catch (error) {
      if (error instanceof DuplicateKeyError) {
        throw new HttpError(409, "Username already taken");
      }
      throw error;
    }
    return { id: user.id, username };
  }

  async verifyPassword(rawUsername: unknown, password: unknown): Promise<User> {
    const username = typeof rawUsername === "string" ? rawUsername.trim().toLowerCase() : "";
    const pw = typeof password === "string" ? password : "";
    const user = username ? await this.repo.users.findByUsername(username) : null;
    // Always run argon2 so response time does not reveal whether the user exists
    const hash = user?.passwordHash ?? (await this.getDummyHash());
    const ok = await argon2.verify(hash, pw).catch(() => false);
    if (!user || !ok) {
      throw new HttpError(401, "Invalid username or password");
    }
    if (argon2.needsRehash(user.passwordHash, ARGON2_OPTIONS)) {
      const passwordHash = await argon2.hash(pw, ARGON2_OPTIONS);
      await this.repo.users.updatePasswordHash(user.id, passwordHash);
    }
    return user;
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
    await this.repo.authRequests.create({
      id: requestId,
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
    const req = await this.repo.authRequests.findActive(requestId, new Date());
    if (!req) {
      throw new HttpError(400, "Authorization request expired or not found — please start sign-in again");
    }
  }

  /** User authenticated: consume the authorization request and issue a one-time code. */
  async completeAuthRequest(requestId: string, userId: string): Promise<{ redirect: string }> {
    const req = await this.repo.authRequests.consumeActive(requestId, new Date());
    if (!req) {
      throw new HttpError(400, "Authorization request expired or not found — please start sign-in again");
    }
    const code = randomToken();
    await this.repo.authCodes.create({
      id: sha256(code),
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
    const current = await this.repo.tokens.rotateRefresh(tokenHash);
    if (!current) {
      const reused = await this.repo.tokens.findRefresh(tokenHash);
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
    const doc = (await this.repo.tokens.findRefresh(hash)) ?? (await this.repo.tokens.findAccess(hash));
    if (doc) {
      await this.revokeFamily(doc.familyId);
    }
  }

  // ---------------------------------------------------------------- bearer validation

  async authenticate(accessToken: string): Promise<AuthenticatedUser | null> {
    const token = await this.repo.tokens.findActiveAccess(sha256(accessToken), new Date());
    if (!token) return null;
    const user = await this.repo.users.findById(token.userId);
    if (!user) return null;
    return { id: user.id, username: user.username, scope: token.scope, clientId: token.clientId };
  }

  // ---------------------------------------------------------------- helpers

  private async issueTokens(userId: string, clientId: string, scope: string, familyId: string): Promise<TokenResponse> {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const { accessTokenTtlSec, refreshTokenTtlSec } = this.oauth;
    await this.repo.tokens.createPair(
      { id: sha256(accessToken), userId, clientId, scope, familyId, expiresAt: later(accessTokenTtlSec * 1000) },
      {
        id: sha256(refreshToken),
        userId,
        clientId,
        scope,
        familyId,
        revoked: false,
        expiresAt: later(refreshTokenTtlSec * 1000)
      }
    );
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: accessTokenTtlSec,
      refresh_token: refreshToken,
      scope
    };
  }

  private revokeFamily(familyId: string): Promise<void> {
    return this.repo.tokens.revokeFamily(familyId);
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
