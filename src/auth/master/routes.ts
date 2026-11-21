// /auth/master/*: master sign-in — password, then a code / link to the master's email, then a session token.

import type { Hono } from "hono";
import { parseJsonBody } from "../../shared/http.js";
import type { AuthEnv } from "../../shared/middleware.js";
import { bearerToken, type RequestContext } from "../http.js";
import { masterCodeBody, masterLoginBody, masterStatusBody } from "../schemas.js";
import type { MasterAuthService } from "./auth.js";

export function registerMasterRoutes(app: Hono<AuthEnv>, { masterAuth, ctx }: { masterAuth: MasterAuthService; ctx: RequestContext }) {
  /** { username, password } -> { verify } (code or link sent to the master's email) */
  app.post("/auth/master/login", async (c) => {
    const { username, password } = await parseJsonBody(c, masterLoginBody);
    return c.json(await masterAuth.login(username, password, ctx.mail(c)));
  });

  /** { challengeId, code } -> { access_token, expires_in } */
  app.post("/auth/master/verify", async (c) => {
    c.header("Cache-Control", "no-store");
    const { challengeId, code } = await parseJsonBody(c, masterCodeBody);
    return c.json(await masterAuth.verifyCode(challengeId, code));
  });

  /** { challengeId } -> { pending } | { access_token, ... } (link opened) */
  app.post("/auth/master/status", async (c) => {
    c.header("Cache-Control", "no-store");
    const { challengeId } = await parseJsonBody(c, masterStatusBody);
    return c.json(await masterAuth.status(challengeId));
  });

  /** (Bearer master session) */
  app.post("/auth/master/logout", async (c) => {
    await masterAuth.logout(bearerToken(c));
    return c.body(null, 204);
  });
}
