import type { Context } from "hono";
import {
  authorizeQuery,
  credentialIdParam,
  passkeyLoginOptionsBody,
  passkeyLoginVerifyBody,
  passkeyRegisterVerifyBody,
  passwordLoginBody,
  registerBody,
  parseTokenRequest,
  revokeBody,
  updateAccountBody
} from "./schemas.js";
import { parse, parseJsonBody } from "../shared/http.js";
import type { AuthEnv } from "../shared/middleware.js";
import type { AuthService } from "./service.js";
import type { WebAuthnService } from "./webauthn.js";

export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly webauthn: WebAuthnService
  ) {}

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
      codeChallengeMethod: q.code_challenge_method
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

  async register(c: Context) {
    const body = await parseJsonBody(c, registerBody);
    return c.json(await this.auth.register(body), 201);
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

  async loginPassword(c: Context) {
    const body = await parseJsonBody(c, passwordLoginBody);
    await this.auth.assertAuthRequest(body.request_id);
    const user = await this.auth.verifyPassword(body.username, body.password);
    return c.json(await this.auth.completeAuthRequest(body.request_id, user.id));
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
    return c.json(await this.auth.completeAuthRequest(body.request_id, userId));
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
}
