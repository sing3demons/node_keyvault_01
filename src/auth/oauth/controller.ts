// /.well-known/* and /oauth/*: the OAuth 2.0 / OpenID Connect endpoints.

import { Controller, Get, Post, UseInterceptors, type Ctx } from "../../common/kp/index.js";
import { Bearer } from "../../shared/middleware.js";
import type { ClientCredentials } from "../clients/clients.js";
import { authorizeQuery, introspectBody, parseTokenRequest, revokeBody } from "../schemas.js";
import type { IdTokenIssuer } from "./oidc.js";
import { OAuthError } from "./protocol.js";
import { API_SCOPES, type OAuthService } from "./service.js";

/** OpenID Connect discovery. */
@Controller("/.well-known")
export class DiscoveryController {
  constructor(private readonly idTokens: IdTokenIssuer) {}

  @Get("/openid-configuration")
  configuration(c: Ctx) {
    return c.json(this.idTokens.discovery(API_SCOPES));
  }

  /** Public keys for verifying ID Tokens. */
  @Get("/jwks.json")
  jwks(c: Ctx) {
    c.header("Cache-Control", "public, max-age=300");
    return c.json(this.idTokens.jwks());
  }
}

@Controller("/oauth")
export class OAuthController {
  constructor(private readonly oauth: OAuthService) {}

  /** Validate and hand off to the SPA login page. */
  @Get("/authorize")
  async authorize(c: Ctx) {
    const q = c.safeQuery(authorizeQuery);
    const result = await this.oauth.createAuthRequest({
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

  /** application/x-www-form-urlencoded (RFC 6749 §4.1.3, §4.4.2, §6). */
  @Post("/token")
  async token(c: Ctx) {
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    // OAuthError is an HttpError, so app.onError renders the RFC 6749 §5.2 body (headers above are kept)
    const req = parseTokenRequest(await c.req.parseBody());
    const client = clientCredentials(c, req);
    const tokens = await withClientChallenge(c, client, () => {
      switch (req.grant_type) {
        case "authorization_code":
          return this.oauth.exchangeCode({ code: req.code, redirectUri: req.redirect_uri, client, codeVerifier: req.code_verifier });
        case "refresh_token":
          return this.oauth.refresh({ refreshToken: req.refresh_token, client, scope: req.scope });
        case "client_credentials":
          return this.oauth.clientCredentials({ client, scope: req.scope });
      }
    });
    return c.json(tokens);
  }

  /** RFC 7009: the client authenticates (401 if it fails); otherwise always 200, even for unknown tokens. */
  @Post("/revoke")
  async revoke(c: Ctx) {
    const form = await c.req.parseBody().catch(() => ({}));
    const body = revokeBody.safeParse(form);
    const data = body.success ? body.data : {};
    const client = clientCredentials(c, data);
    await withClientChallenge(c, client, () => this.oauth.revoke(data.token, client));
    return c.body(null, 200);
  }

  /** RFC 7662, for confidential clients (resource servers). */
  @Post("/introspect")
  async introspect(c: Ctx) {
    c.header("Cache-Control", "no-store");
    const form = await c.req.parseBody().catch(() => ({}));
    const body = introspectBody.safeParse(form);
    const data = body.success ? body.data : {};
    const client = clientCredentials(c, data);
    return c.json(await withClientChallenge(c, client, () => this.oauth.introspect(data.token, client)));
  }

  @Get("/userinfo")
  @UseInterceptors(Bearer)
  async userInfo(c: Ctx) {
    const user = c.get("user");
    return c.json(await this.oauth.userInfo(user.id, user.scope));
  }
}

/**
 * Client authentication (RFC 6749 §2.3.1): HTTP Basic, or client_id + client_secret in the form, or a
 * public client's client_id alone. Using more than one method is an error.
 */
function clientCredentials(c: Ctx, form: { client_id?: string; client_secret?: string }): ClientCredentials {
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
async function withClientChallenge<T>(c: Ctx, client: ClientCredentials, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof OAuthError && error.error === "invalid_client" && client.via === "basic") {
      c.header("WWW-Authenticate", 'Basic realm="oauth"');
    }
    throw error;
  }
}
