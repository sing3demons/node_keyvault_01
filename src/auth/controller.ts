import type { Context } from "hono";
import { OAuthError } from "./errors.js";
import type { AuthEnv } from "./middleware.js";
import type { AuthService } from "./service.js";
import type { CredentialJSON, WebAuthnService } from "./webauthn.js";

type Body = Record<string, unknown>;
const readJson = async (c: Context): Promise<Body> => ((await c.req.json().catch(() => null)) as Body | null) ?? {};
const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly webauthn: WebAuthnService
  ) {}

  // ================================================================ OAuth2 endpoints

  /** GET /oauth/authorize — validate and hand off to the SPA login page. */
  async authorize(c: Context) {
    const q = c.req.query();
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
    try {
      const body = await c.req.parseBody();
      const p = (k: string) => str(body[k]);
      switch (p("grant_type")) {
        case "authorization_code":
          return c.json(
            await this.auth.exchangeCode({
              code: p("code"),
              redirectUri: p("redirect_uri"),
              clientId: p("client_id"),
              codeVerifier: p("code_verifier")
            })
          );
        case "refresh_token":
          return c.json(
            await this.auth.refresh({ refreshToken: p("refresh_token"), clientId: p("client_id"), scope: p("scope") })
          );
        case undefined:
          throw new OAuthError("invalid_request", "grant_type is required");
        default:
          throw new OAuthError("unsupported_grant_type", "Supported: authorization_code, refresh_token");
      }
    } catch (error) {
      if (error instanceof OAuthError) {
        return c.json({ error: error.error, error_description: error.message }, error.statusCode as 400 | 401);
      }
      throw error;
    }
  }

  /** POST /oauth/revoke — RFC 7009, always 200. */
  async revoke(c: Context) {
    const body = await c.req.parseBody().catch(() => ({}) as Record<string, unknown>);
    await this.auth.revoke(str(body.token));
    return c.body(null, 200);
  }

  /** GET /oauth/userinfo (Bearer) */
  async userinfo(c: Context<AuthEnv>) {
    const user = c.get("user");
    return c.json({ sub: user.id, username: user.username, scope: user.scope });
  }

  // ================================================================ /auth (used by the login page)

  async register(c: Context) {
    const body = await readJson(c);
    const user = await this.auth.register(body.username, body.password);
    return c.json(user, 201);
  }

  async loginPassword(c: Context) {
    const body = await readJson(c);
    const requestId = str(body.request_id);
    await this.auth.assertAuthRequest(requestId);
    const user = await this.auth.verifyPassword(body.username, body.password);
    return c.json(await this.auth.completeAuthRequest(requestId!, user._id));
  }

  async passkeyLoginOptions(c: Context) {
    const body = await readJson(c);
    const requestId = str(body.request_id);
    await this.auth.assertAuthRequest(requestId);
    return c.json(await this.webauthn.loginOptions(requestId!));
  }

  async passkeyLoginVerify(c: Context) {
    const body = await readJson(c);
    const requestId = str(body.request_id);
    await this.auth.assertAuthRequest(requestId);
    const userId = await this.webauthn.verifyLogin(body.challengeId, requestId!, body.credential as CredentialJSON);
    return c.json(await this.auth.completeAuthRequest(requestId!, userId));
  }

  // ================================================================ passkey management (Bearer)

  async passkeyRegisterOptions(c: Context<AuthEnv>) {
    const user = c.get("user");
    return c.json(await this.webauthn.registrationOptions(user.id, user.username));
  }

  async passkeyRegisterVerify(c: Context<AuthEnv>) {
    const user = c.get("user");
    const body = await readJson(c);
    const created = await this.webauthn.verifyRegistration(
      user.id,
      body.challengeId,
      body.credential as CredentialJSON,
      body.name
    );
    return c.json(created, 201);
  }

  async listPasskeys(c: Context<AuthEnv>) {
    return c.json({ passkeys: await this.webauthn.list(c.get("user").id) });
  }

  async deletePasskey(c: Context<AuthEnv>) {
    await this.webauthn.remove(c.get("user").id, c.req.param("id") ?? "");
    return c.body(null, 204);
  }
}
