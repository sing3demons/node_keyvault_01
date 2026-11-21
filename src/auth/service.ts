import { randomUUID } from "node:crypto";
import { randomToken, sha256 } from "../shared/crypto.js";
import { HttpError } from "../shared/http.js";
import type { SecretHasher } from "../shared/hashing.js";
import type { AuthenticatedUser, TokenAuthenticator } from "../shared/middleware.js";
import { expiresIn } from "../shared/util.js";
import { OAuthError, verifyPkceS256 } from "./oauth.js";
import { OIDC_SCOPES, type IdTokenIssuer } from "./oidc.js";
import { displayProfile, isPassword, type LocalizedProfile, type Role, type User, type UserSummary } from "./model.js";
import { DuplicateKeyError, type AuthRepository } from "./repository.js";
import type { RegisterBody, UpdateAccountBody } from "./schemas.js";

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
  nonce?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
  /** Present when the grant includes the "openid" scope. */
  id_token?: string;
}

/** Scopes protecting this API (as opposed to the OIDC identity scopes). */
export const API_SCOPES = ["secrets"] as const;
const SUPPORTED_SCOPES = new Set<string>([...OIDC_SCOPES, ...API_SCOPES]);
const DEFAULT_SCOPE = "secrets";
const AUTH_REQUEST_TTL_MS = 10 * 60_000;
const AUTH_CODE_TTL_MS = 60_000;

/** Public view of a user (never includes credentials). */
export interface Account {
  id: string;
  username: string;
  email?: string;
  profiles: LocalizedProfile[];
  preferredLang?: string;
  /** Profile in preferredLang, else the first one. */
  displayProfile?: LocalizedProfile;
  roles: Role[];
  createdAt: string;
}

/** Admin listing row. */
export interface UserView {
  id: string;
  username: string;
  email?: string;
  roles: Role[];
  createdAt: string;
}

const toUserView = (u: UserSummary): UserView => ({
  id: u.id,
  username: u.username,
  ...(u.email !== undefined ? { email: u.email } : {}),
  roles: u.roles,
  createdAt: u.createdAt.toISOString()
});

/** OpenID Connect UserInfo claims (OIDC Core §5.1), with per-language profiles as "claim#lang" (§5.2). */
export type UserInfoClaims = Record<string, string | boolean>;

const toAccount = (u: User): Account => ({
  id: u.id,
  username: u.username,
  ...(u.email !== undefined ? { email: u.email } : {}),
  profiles: u.profiles,
  ...(u.preferredLang !== undefined ? { preferredLang: u.preferredLang } : {}),
  ...(displayProfile(u) ? { displayProfile: displayProfile(u) } : {}),
  roles: u.roles,
  createdAt: u.createdAt.toISOString()
});

export class AuthService implements TokenAuthenticator {
  constructor(
    private readonly repo: AuthRepository,
    private readonly hasher: SecretHasher,
    private readonly oauth: OAuthSettings,
    private readonly idTokens: IdTokenIssuer,
    /** Bootstrap admins (ADMIN_USERNAMES), lowercased. */
    private readonly adminUsernames: readonly string[] = []
  ) {}

  // ---------------------------------------------------------------- roles

  /** Startup: give the admin role to ADMIN_USERNAMES users that already exist. */
  async bootstrapAdmins(): Promise<void> {
    for (const username of this.adminUsernames) {
      const user = await this.repo.users.findByUsername(username);
      if (user && !user.roles.includes("admin")) await this.repo.users.setRoles(user.id, [...user.roles, "admin"]);
    }
  }

  async listUsers(): Promise<UserView[]> {
    return (await this.repo.users.list()).map(toUserView);
  }

  /** Admin only (enforced by the route). The last admin cannot lose the role, so nobody gets locked out. */
  async setUserRoles(username: string, roles: Role[]): Promise<UserView> {
    const target = await this.repo.users.findByUsername(username.trim().toLowerCase());
    if (!target) throw new HttpError(404, `User "${username}" not found`);
    const next = [...new Set(roles)];
    if (target.roles.includes("admin") && !next.includes("admin")) {
      const admins = (await this.repo.users.list()).filter((u) => u.roles.includes("admin"));
      if (admins.length <= 1) throw new HttpError(409, "Cannot remove the last admin", "conflict");
    }
    await this.repo.users.setRoles(target.id, next);
    return toUserView({ ...target, roles: next });
  }

  // ---------------------------------------------------------------- users

  /** Input is already validated and normalized by `registerBody`. */
  async register({ username, email, password, profiles, preferredLang }: RegisterBody): Promise<Account> {
    const now = new Date();
    const user: User = {
      id: randomUUID(),
      username,
      email,
      profiles,
      ...(preferredLang !== undefined ? { preferredLang } : {}),
      credentials: [{ id: randomUUID(), type: "password", ...(await this.hasher.hash(password)), createdAt: now }],
      roles: this.adminUsernames.includes(username) ? ["admin"] : [],
      createdAt: now
    };
    try {
      await this.repo.users.create(user);
    } catch (error) {
      throw this.conflict(error);
    }
    return toAccount(user);
  }

  // ---------------------------------------------------------------- profile

  async getAccount(userId: string): Promise<Account> {
    return toAccount(await this.requireUser(userId));
  }

  /** Input is validated by `updateAccountBody`; preferredLang is re-checked against the stored profiles. */
  async updateAccount(userId: string, update: UpdateAccountBody): Promise<Account> {
    const user = await this.requireUser(userId);
    const profiles = update.profiles ?? user.profiles;
    let preferredLang = update.preferredLang;
    if (typeof preferredLang === "string" && !profiles.some((n) => n.lang === preferredLang)) {
      throw new HttpError(400, `preferredLang "${preferredLang}" is not one of your profile languages`);
    }
    // profiles replaced without the current preference => fall back to the first name
    if (preferredLang === undefined && user.preferredLang && !profiles.some((n) => n.lang === user.preferredLang)) {
      preferredLang = null;
    }
    try {
      await this.repo.users.updateAccount(userId, { ...update, preferredLang });
    } catch (error) {
      throw this.conflict(error);
    }
    return this.getAccount(userId);
  }

  /** Claims for /oauth/userinfo: `sub` plus whatever the token's scopes allow. */
  async userInfo(userId: string, scope: string): Promise<UserInfoClaims> {
    const user = await this.requireUser(userId);
    return { sub: user.id, ...this.scopedClaims(user, scope) };
  }

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
      claims.email_verified = false; // addresses are not verified yet
    }
    return claims;
  }

  async verifyPassword(username: string, password: string): Promise<User> {
    const user = await this.repo.users.findByUsername(username);
    const credential = user?.credentials.find(isPassword);
    // runs even without a credential, so timing does not reveal whether the user exists
    const result = await this.hasher.verify(credential, password);
    if (!user || !credential || !result.ok) {
      throw new HttpError(401, "Invalid username or password", "access_denied");
    }
    if (result.needsRehash) {
      const { value, algorithm } = await this.hasher.hash(password);
      await this.repo.users.updateSecret(user.id, credential.id, value, algorithm);
    }
    return user;
  }

  // ---------------------------------------------------------------- /oauth/authorize

  /**
   * Validates an authorization request. Errors about client/redirect_uri are thrown as HttpError
   * (must NOT redirect); everything else is returned as a redirect to the client with `error`.
   */
  async createAuthRequest(p: AuthorizeParams): Promise<{ requestId: string } | { redirect: string }> {
    if (p.clientId !== this.oauth.clientId) {
      throw new HttpError(400, "Unknown client_id", "invalid_client");
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
      ...(p.nonce !== undefined ? { nonce: p.nonce } : {}),
      expiresAt: expiresIn(AUTH_REQUEST_TTL_MS)
    });
    return { requestId };
  }

  /** Throws if the pending authorization request does not exist / expired (does not consume it). */
  async assertAuthRequest(requestId: string): Promise<void> {
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
      ...(req.nonce !== undefined ? { nonce: req.nonce } : {}),
      authTime: new Date(),
      used: false,
      expiresAt: expiresIn(AUTH_CODE_TTL_MS)
    });
    return { redirect: this.buildRedirect(req.redirectUri, { code, state: req.state }) };
  }

  // ---------------------------------------------------------------- /oauth/token

  async exchangeCode(p: {
    code: string;
    redirectUri: string;
    clientId: string;
    codeVerifier: string;
  }): Promise<TokenResponse> {
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
    return this.issueTokens(codeDoc.userId, codeDoc.clientId, codeDoc.scope, codeDoc.familyId, {
      authTime: codeDoc.authTime ?? new Date(),
      nonce: codeDoc.nonce
    });
  }

  async refresh(p: { refreshToken: string; clientId: string; scope?: string }): Promise<TokenResponse> {
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
    // OIDC Core §12.2: refreshed ID Tokens keep auth_time; nonce is not repeated
    return this.issueTokens(current.userId, current.clientId, scope, current.familyId, {
      authTime: current.authTime ?? new Date()
    });
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
    return { id: user.id, username: user.username, scope: token.scope, clientId: token.clientId, roles: user.roles };
  }

  // ---------------------------------------------------------------- helpers

  private async requireUser(userId: string): Promise<User> {
    const user = await this.repo.users.findById(userId);
    if (!user) throw new HttpError(404, "User not found");
    return user;
  }

  /** DuplicateKeyError -> 409 naming what is taken; anything else passes through. */
  private conflict(error: unknown): unknown {
    if (!(error instanceof DuplicateKeyError)) return error;
    if (error.field === "email") return new HttpError(409, "Email already registered");
    if (error.field === "username") return new HttpError(409, "Username already taken");
    return new HttpError(409, error.message);
  }

  private async issueTokens(
    userId: string,
    clientId: string,
    scope: string,
    familyId: string,
    session: { authTime: Date; nonce?: string }
  ): Promise<TokenResponse> {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const { accessTokenTtlSec, refreshTokenTtlSec } = this.oauth;
    await this.repo.tokens.createPair(
      { id: sha256(accessToken), userId, clientId, scope, familyId, expiresAt: expiresIn(accessTokenTtlSec * 1000) },
      {
        id: sha256(refreshToken),
        userId,
        clientId,
        scope,
        familyId,
        revoked: false,
        authTime: session.authTime,
        expiresAt: expiresIn(refreshTokenTtlSec * 1000)
      }
    );
    const response: TokenResponse = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: accessTokenTtlSec,
      refresh_token: refreshToken,
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
        claims: this.scopedClaims(user, scope)
      });
    }
    return response;
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
