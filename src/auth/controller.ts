import type { Context } from "hono";
import { getConnInfo } from "@hono/node-server/conninfo";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { randomToken } from "../shared/crypto.js";
import type { ClientCredentials, ClientService } from "./clients.js";
import type { Actor, ClientOwnerService } from "./client-owners.js";
import type { MasterAuthService } from "./master.js";
import type { DeviceContext } from "./devices.js";
import type { MailContext } from "./email-codes.js";
import { OAuthError } from "./oauth.js";
import {
  authorizeQuery,
  clientIdParam,
  clientMetadataBody,
  emailLinkResumeBody,
  introspectBody,
  masterCodeBody,
  masterLoginBody,
  masterStatusBody,
  credentialIdParam,
  emailCodeBody,
  emailLinkBody,
  emailResendBody,
  emailStatusBody,
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
/** An opened sign-in link waiting for the client's fresh authorization request (httpOnly, /auth only). */
const EMAIL_LINK_COOKIE = "kv_email_link";
/** Readable flag so the login page knows to ask for it (carries nothing secret). */
const EMAIL_LINK_FLAG_COOKIE = "kv_email_link_pending";

export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly webauthn: WebAuthnService,
    private readonly idTokens: IdTokenIssuer,
    private readonly clients: ClientService,
    private readonly owners: ClientOwnerService,
    private readonly masterAuth: MasterAuthService,
    /** Origins the login / account pages run on (WEBAUTHN_ORIGINS); emailed links open one of these. */
    private readonly uiOrigins: string[],
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
    const client = this.clientCredentials(c, req);
    const tokens = await this.withClientChallenge(c, client, () => {
      switch (req.grant_type) {
        case "authorization_code":
          return this.auth.exchangeCode({ code: req.code, redirectUri: req.redirect_uri, client, codeVerifier: req.code_verifier });
        case "refresh_token":
          return this.auth.refresh({ refreshToken: req.refresh_token, client, scope: req.scope });
        case "client_credentials":
          return this.auth.clientCredentials({ client, scope: req.scope });
      }
    });
    return c.json(tokens);
  }

  /** POST /oauth/introspect — RFC 7662, for confidential clients (resource servers). */
  async introspect(c: Context) {
    c.header("Cache-Control", "no-store");
    const form = await c.req.parseBody().catch(() => ({}));
    const body = introspectBody.safeParse(form);
    const data = body.success ? body.data : {};
    const client = this.clientCredentials(c, data);
    return c.json(await this.withClientChallenge(c, client, () => this.auth.introspect(data.token, client)));
  }

  /**
   * POST /oauth/revoke — RFC 7009: the client authenticates like at the token endpoint (401 if it fails);
   * otherwise always 200, even for unknown, foreign or malformed tokens.
   */
  async revoke(c: Context) {
    const form = await c.req.parseBody().catch(() => ({}));
    const body = revokeBody.safeParse(form);
    const data = body.success ? body.data : {};
    const client = this.clientCredentials(c, data);
    await this.withClientChallenge(c, client, () => this.auth.revoke(data.token, client));
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
    return c.json(await this.auth.register(body, this.mail(c)), 201);
  }

  /** POST /auth/email/verify — { challengeId, code, request_id? } -> { redirect } (sign-in) | { verified: true } */
  async confirmEmailCode(c: Context) {
    const body = await parseJsonBody(c, emailCodeBody);
    const device = body.request_id !== undefined ? this.device(c) : undefined;
    return c.json(await this.auth.confirmEmailCode(body.challengeId, body.code, body.request_id, device));
  }

  /**
   * POST /auth/email/link — { challengeId, token, request_id? } from the emailed link.
   * -> { verified } | { redirect } | { continue: <client initiate_login_uri> } (the link is kept in a cookie
   * for the login page of the authorization request the client then starts: /auth/email/link/resume).
   */
  async openEmailLink(c: Context) {
    const body = await parseJsonBody(c, emailLinkBody);
    const result = await this.auth.openEmailLink(body.challengeId, body.token, this.device(c), body.request_id);
    if (!("continue" in result)) return c.json(result);
    const secure = new URL(c.req.url).protocol === "https:";
    const { value, maxAgeSec } = result.resume;
    setCookie(c, EMAIL_LINK_COOKIE, value, { httpOnly: true, sameSite: "Lax", secure, path: "/auth", maxAge: maxAgeSec });
    setCookie(c, EMAIL_LINK_FLAG_COOKIE, "1", { sameSite: "Lax", secure, path: "/", maxAge: maxAgeSec });
    return c.json({ continue: result.continue });
  }

  /** POST /auth/email/link/resume — { request_id } -> { redirect }: finish the sign-in the link started. */
  async resumeEmailLink(c: Context) {
    const { request_id } = await parseJsonBody(c, emailLinkResumeBody);
    const cookie = getCookie(c, EMAIL_LINK_COOKIE);
    // single use either way
    deleteCookie(c, EMAIL_LINK_COOKIE, { path: "/auth" });
    deleteCookie(c, EMAIL_LINK_FLAG_COOKIE, { path: "/" });
    return c.json(await this.auth.resumeEmailLink(cookie, request_id, this.device(c)));
  }

  /** POST /auth/email/status — { challengeId } (account page, verify link) -> { pending } | { verified } */
  async emailChallengeStatus(c: Context) {
    c.header("Cache-Control", "no-store");
    const { challengeId } = await parseJsonBody(c, emailStatusBody);
    return c.json(await this.auth.emailChallengeStatus(challengeId));
  }

  /** POST /auth/email/resend — { challengeId } -> a fresh code / link is emailed */
  async resendEmailCode(c: Context) {
    const { challengeId } = await parseJsonBody(c, emailResendBody);
    return c.json(await this.auth.resendEmailCode(challengeId, this.mail(c)));
  }

  /** POST /auth/me/email/verification (Bearer) — emails a code / link (per the token's client) */
  async startEmailVerification(c: Context<AuthEnv>) {
    const user = c.get("user");
    return c.json(await this.auth.startEmailVerification(user.id, user.clientId, this.mail(c)));
  }

  // ================================================================ OAuth clients (admin; RFC 7591 / 7592 metadata)

  /** GET /admin/clients */
  async listClients(c: Context<AuthEnv>) {
    return c.json({ clients: await this.clients.list() });
  }

  /** GET /admin/clients/:id */
  async getClient(c: Context<AuthEnv>) {
    return c.json(await this.clients.get(parse(clientIdParam, c.req.param()).id));
  }

  /** POST /admin/clients — RFC 7591 §3.1; the response carries client_secret once (confidential clients). */
  async registerClient(c: Context<AuthEnv>) {
    c.header("Cache-Control", "no-store");
    return c.json(await this.clients.register(await parseJsonBody(c, clientMetadataBody)), 201);
  }

  /** PUT /admin/clients/:id — RFC 7592 §2.2: complete metadata (omitted optional fields are cleared). */
  async updateClient(c: Context<AuthEnv>) {
    c.header("Cache-Control", "no-store");
    const { id } = parse(clientIdParam, c.req.param());
    return c.json(await this.clients.update(id, await parseJsonBody(c, clientMetadataBody)));
  }

  /** POST /admin/clients/:id/secret — new client_secret (the old one stops working). */
  async rotateClientSecret(c: Context<AuthEnv>) {
    c.header("Cache-Control", "no-store");
    return c.json(await this.clients.rotateSecret(parse(clientIdParam, c.req.param()).id));
  }

  /** DELETE /admin/clients/:id — also revokes its tokens (RFC 7592 §2.3). */
  async deleteClient(c: Context<AuthEnv>) {
    // the master credential is not signed in through any client, so there is nothing to protect
    const callerClientId = c.get("master") ? undefined : c.get("user").clientId;
    await this.clients.delete(parse(clientIdParam, c.req.param()).id, callerClientId);
    return c.body(null, 204);
  }

  // ================================================================ master sign-in (MASTER_CREDENTIALS + email)

  /** POST /auth/master/login — { username, password } -> { verify } (code or link sent to the master's email) */
  async masterLogin(c: Context) {
    const { username, password } = await parseJsonBody(c, masterLoginBody);
    return c.json(await this.masterAuth.login(username, password, this.mail(c)));
  }

  /** POST /auth/master/verify — { challengeId, code } -> { access_token, expires_in } */
  async masterVerify(c: Context) {
    c.header("Cache-Control", "no-store");
    const { challengeId, code } = await parseJsonBody(c, masterCodeBody);
    return c.json(await this.masterAuth.verifyCode(challengeId, code));
  }

  /** POST /auth/master/status — { challengeId } -> { pending } | { access_token, ... } (link opened) */
  async masterStatus(c: Context) {
    c.header("Cache-Control", "no-store");
    const { challengeId } = await parseJsonBody(c, masterStatusBody);
    return c.json(await this.masterAuth.status(challengeId));
  }

  /** POST /auth/master/logout (Bearer master session) */
  async masterLogout(c: Context) {
    await this.masterAuth.logout(/^Bearer\s+(\S+)$/i.exec(c.req.header("Authorization") ?? "")?.[1]);
    return c.body(null, 204);
  }

  // ================================================================ client owners (client_admin or master)

  /** GET /admin/client-owners -> { owners, master: { configured, enabled, disabledAt?, disabledBy? } } */
  async listClientOwners(c: Context<AuthEnv>) {
    return c.json({ ...(await this.owners.view()), you: this.actor(c) });
  }

  /** PUT /admin/client-owners/:username — give the client_admin role */
  async addClientOwner(c: Context<AuthEnv>) {
    return c.json(await this.owners.addOwner(parse(usernameParam, c.req.param()).username));
  }

  /** DELETE /admin/client-owners/:username — never the last one while the master is disabled */
  async removeClientOwner(c: Context<AuthEnv>) {
    return c.json(await this.owners.removeOwner(parse(usernameParam, c.req.param()).username));
  }

  /** POST /admin/client-owners/master/disable — needs another owner; MASTER_CREDENTIALS stops working */
  async disableMaster(c: Context<AuthEnv>) {
    return c.json(await this.owners.disableMaster(this.actor(c)));
  }

  /** POST /admin/client-owners/master/enable — owners only */
  async enableMaster(c: Context<AuthEnv>) {
    return c.json(await this.owners.enableMaster(this.actor(c)));
  }

  private actor(c: Context<AuthEnv>): Actor {
    const master = c.get("master");
    if (master) return { kind: "master", name: master.username };
    const user = c.get("user");
    return { kind: "user", id: user.id, username: user.username };
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
    return c.json(
      await this.auth.loginWithPassword(body.request_id, body.username, body.password, this.device(c), this.mail(c))
    );
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

  /**
   * Client authentication (RFC 6749 §2.3.1): HTTP Basic, or client_id + client_secret in the form, or a
   * public client's client_id alone. Using more than one method is an error.
   */
  private clientCredentials(c: Context, form: { client_id?: string; client_secret?: string }): ClientCredentials {
    const basic = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(c.req.header("Authorization") ?? "");
    if (basic) {
      if (form.client_secret !== undefined) {
        throw new OAuthError("invalid_request", "Use only one client authentication method");
      }
      const decoded = Buffer.from(basic[1]!, "base64").toString("utf8");
      const sep = decoded.indexOf(":");
      // RFC 6749 §2.3.1: both parts are application/x-www-form-urlencoded
      const unform = (v: string) => {
        try {
          return decodeURIComponent(v.replace(/\+/g, " "));
        } catch {
          return v;
        }
      };
      const clientId = unform(sep < 0 ? decoded : decoded.slice(0, sep));
      if (form.client_id !== undefined && form.client_id !== clientId) {
        throw new OAuthError("invalid_request", "client_id does not match the Authorization header");
      }
      return { clientId, clientSecret: sep < 0 ? "" : unform(decoded.slice(sep + 1)), via: "basic" };
    }
    if (form.client_secret !== undefined) return { clientId: form.client_id, clientSecret: form.client_secret, via: "post" };
    return { clientId: form.client_id, via: "none" };
  }

  /** RFC 6749 §5.2: a failed Basic authentication answers 401 with a WWW-Authenticate challenge. */
  private async withClientChallenge<T>(c: Context, client: ClientCredentials, run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (error) {
      if (error instanceof OAuthError && error.error === "invalid_client" && client.via === "basic") {
        c.header("WWW-Authenticate", 'Basic realm="oauth"');
      }
      throw error;
    }
  }

  /** Emailed links open the auth UI the request came from (only allow-listed origins). */
  private mail(c: Context): MailContext {
    const origin = c.req.header("origin");
    return { uiOrigin: origin && this.uiOrigins.includes(origin) ? origin : this.uiOrigins[0]! };
  }

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
