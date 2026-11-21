import type { Context } from "hono";
import { getConnInfo } from "@hono/node-server/conninfo";
import { getCookie, setCookie } from "hono/cookie";
import { randomToken } from "../shared/crypto.js";
import type { DeviceContext } from "./devices.js";
import {
  authorizeQuery,
  credentialIdParam,
  emailCodeBody,
  emailResendBody,
  passkeyLoginOptionsBody,
  passkeyLoginVerifyBody,
  passkeyRegisterVerifyBody,
  passwordLoginBody,
  registerBody,
  parseTokenRequest,
  revokeBody,
  setRolesBody,
  usernameParam,
  updateAccountBody
} from "./schemas.js";
import { parse, parseJsonBody } from "../shared/http.js";
import type { AuthEnv } from "../shared/middleware.js";
import type { IdTokenIssuer } from "./oidc.js";
import { API_SCOPES, type AuthService } from "./service.js";
import type { WebAuthnService } from "./webauthn.js";

/** httpOnly cookie that recognizes a browser across sign-ins (value is random; only its hash is stored). */
const DEVICE_COOKIE = "kv_device";
const DEVICE_COOKIE_MAX_AGE = 400 * 24 * 60 * 60; // browsers cap cookie lifetime at 400 days

export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly webauthn: WebAuthnService,
    private readonly idTokens: IdTokenIssuer,
    /** Read the client IP from X-Forwarded-For (TRUST_PROXY). */
    private readonly trustProxy = false
  ) {}

  // ================================================================ OpenID Connect discovery

  /** GET /.well-known/openid-configuration */
  openidConfiguration(c: Context) {
    return c.json(this.idTokens.discovery(API_SCOPES));
  }

  /** GET /.well-known/jwks.json — public keys for verifying ID Tokens */
  jwks(c: Context) {
    c.header("Cache-Control", "public, max-age=300");
    return c.json(this.idTokens.jwks());
  }

  // ================================================================ OAuth2 endpoints

  /** GET /oauth/authorize — validate and hand off to the SPA login page. */
  async authorize(c: Context) {
    const q = parse(authorizeQuery, c.req.query());
    const result = await this.auth.createAuthRequest({
      responseType: q.response_type,
      clientId: q.client_id,
      redirectUri: q.redirect_uri,
      state: q.state,
      scope: q.scope,
      codeChallenge: q.code_challenge,
      codeChallengeMethod: q.code_challenge_method,
      nonce: q.nonce
    });
    if ("redirect" in result) return c.redirect(result.redirect, 302);
    return c.redirect(`/login?request_id=${encodeURIComponent(result.requestId)}`, 302);
  }

  /** POST /oauth/token — application/x-www-form-urlencoded (RFC 6749 §4.1.3, §6). */
  async token(c: Context) {
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    // OAuthError is an HttpError, so app.onError renders the RFC 6749 §5.2 body (headers above are kept)
    const req = parseTokenRequest(await c.req.parseBody());
    const tokens =
      req.grant_type === "authorization_code"
        ? await this.auth.exchangeCode({
            code: req.code,
            redirectUri: req.redirect_uri,
            clientId: req.client_id,
            codeVerifier: req.code_verifier
          })
        : await this.auth.refresh({ refreshToken: req.refresh_token, clientId: req.client_id, scope: req.scope });
    return c.json(tokens);
  }

  /** POST /oauth/revoke — RFC 7009: always 200, even for unknown or malformed tokens. */
  async revoke(c: Context) {
    const form = await c.req.parseBody().catch(() => ({}));
    const body = revokeBody.safeParse(form);
    if (body.success) await this.auth.revoke(body.data.token);
    return c.body(null, 200);
  }

  /** GET /oauth/userinfo (Bearer) */
  async userinfo(c: Context<AuthEnv>) {
    const user = c.get("user");
    return c.json(await this.auth.userInfo(user.id, user.scope));
  }

  // ================================================================ /auth (used by the login page)

  /** POST /auth/register — creates the account and emails a verification code. */
  async register(c: Context) {
    const body = await parseJsonBody(c, registerBody);
    return c.json(await this.auth.register(body), 201);
  }

  /** POST /auth/email/verify — { challengeId, code, request_id? } -> { redirect } (sign-in) | { verified: true } */
  async confirmEmailCode(c: Context) {
    const body = await parseJsonBody(c, emailCodeBody);
    const device = body.request_id !== undefined ? this.device(c) : undefined;
    return c.json(await this.auth.confirmEmailCode(body.challengeId, body.code, body.request_id, device));
  }

  /** POST /auth/email/resend — { challengeId } -> a fresh code is emailed */
  async resendEmailCode(c: Context) {
    const { challengeId } = await parseJsonBody(c, emailResendBody);
    return c.json(await this.auth.resendEmailCode(challengeId));
  }

  /** POST /auth/me/email/verification (Bearer) — emails a code to the current, unverified address */
  async startEmailVerification(c: Context<AuthEnv>) {
    return c.json(await this.auth.startEmailVerification(c.get("user").id));
  }

  // ================================================================ devices (Bearer)

  /** GET /auth/me/devices */
  async listDevices(c: Context<AuthEnv>) {
    const user = c.get("user");
    return c.json({ devices: await this.auth.listDevices(user.id, user.deviceId) });
  }

  /** POST /auth/me/devices/:id/sign-out — revoke the device's sessions, keep it in the history */
  async signOutDevice(c: Context<AuthEnv>) {
    const { id } = parse(credentialIdParam, c.req.param());
    const user = c.get("user");
    await this.auth.signOutDevice(user.id, id, user.deviceId);
    return c.body(null, 204);
  }

  /** DELETE /auth/me/devices/:id — sign the device out and forget it */
  async removeDevice(c: Context<AuthEnv>) {
    const { id } = parse(credentialIdParam, c.req.param());
    const user = c.get("user");
    await this.auth.removeDevice(user.id, id, user.deviceId);
    return c.body(null, 204);
  }

  // ================================================================ admin (requireRole("admin"))

  /** GET /admin/users */
  async listUsers(c: Context<AuthEnv>) {
    return c.json({ users: await this.auth.listUsers() });
  }

  /** PUT /admin/users/:username/roles  body: { roles } */
  async setUserRoles(c: Context<AuthEnv>) {
    const { username } = parse(usernameParam, c.req.param());
    const { roles } = await parseJsonBody(c, setRolesBody);
    return c.json(await this.auth.setUserRoles(username, roles));
  }

  /** GET /auth/me (Bearer) */
  async getAccount(c: Context<AuthEnv>) {
    return c.json(await this.auth.getAccount(c.get("user").id));
  }

  /** PATCH /auth/me (Bearer) — email, profiles, preferredLang */
  async updateAccount(c: Context<AuthEnv>) {
    const body = await parseJsonBody(c, updateAccountBody);
    return c.json(await this.auth.updateAccount(c.get("user").id, body));
  }

  /** POST /auth/login/password -> { redirect } | { verify } (enter the emailed code next) */
  async loginPassword(c: Context) {
    const body = await parseJsonBody(c, passwordLoginBody);
    return c.json(await this.auth.loginWithPassword(body.request_id, body.username, body.password, this.device(c)));
  }

  async passkeyLoginOptions(c: Context) {
    const body = await parseJsonBody(c, passkeyLoginOptionsBody);
    await this.auth.assertAuthRequest(body.request_id);
    return c.json(await this.webauthn.loginOptions(body.request_id));
  }

  async passkeyLoginVerify(c: Context) {
    const body = await parseJsonBody(c, passkeyLoginVerifyBody);
    await this.auth.assertAuthRequest(body.request_id);
    const userId = await this.webauthn.verifyLogin(body.challengeId, body.request_id, body.credential);
    return c.json(await this.auth.completeAuthRequest(body.request_id, userId, { device: this.device(c), method: "passkey" }));
  }

  // ================================================================ passkey management (Bearer)

  async passkeyRegisterOptions(c: Context<AuthEnv>) {
    const user = c.get("user");
    return c.json(await this.webauthn.registrationOptions(user.id, user.username));
  }

  async passkeyRegisterVerify(c: Context<AuthEnv>) {
    const user = c.get("user");
    const body = await parseJsonBody(c, passkeyRegisterVerifyBody);
    const created = await this.webauthn.verifyRegistration(user.id, body.challengeId, body.credential, body.name);
    return c.json(created, 201);
  }

  async listPasskeys(c: Context<AuthEnv>) {
    return c.json({ passkeys: await this.webauthn.list(c.get("user").id) });
  }

  async deletePasskey(c: Context<AuthEnv>) {
    const { id } = parse(credentialIdParam, c.req.param());
    await this.webauthn.remove(c.get("user").id, id);
    return c.body(null, 204);
  }

  // ================================================================ helpers

  /** The browser behind a sign-in request; gives it a device cookie the first time. */
  private device(c: Context): DeviceContext {
    let key = getCookie(c, DEVICE_COOKIE);
    if (!key || !/^[A-Za-z0-9_-]{43}$/.test(key)) {
      key = randomToken();
      setCookie(c, DEVICE_COOKIE, key, {
        httpOnly: true,
        sameSite: "Lax",
        secure: new URL(c.req.url).protocol === "https:",
        path: "/auth",
        maxAge: DEVICE_COOKIE_MAX_AGE
      });
    }
    return { key, userAgent: c.req.header("user-agent") ?? "", ip: this.clientIp(c) };
  }

  private clientIp(c: Context): string | undefined {
    if (this.trustProxy) {
      const forwarded = c.req.header("x-forwarded-for")?.split(",")[0]?.trim();
      if (forwarded) return forwarded.slice(0, 64);
    }
    try {
      return getConnInfo(c).remote.address;
    } catch {
      return undefined; // not running on the Node server (e.g. tests)
    }
  }
}
