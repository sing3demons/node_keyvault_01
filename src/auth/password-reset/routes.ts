// /auth/password/*: forgot password (no sign-in needed).

import type { Hono } from "hono";
import { parseJsonBody } from "../../shared/http.js";
import type { AuthEnv } from "../../shared/middleware.js";
import type { RequestContext } from "../http.js";
import { forgotPasswordBody, resetPasswordBody } from "../schemas.js";
import type { PasswordResetService } from "./service.js";

export function registerPasswordResetRoutes(
  app: Hono<AuthEnv>,
  { passwordReset, ctx }: { passwordReset: PasswordResetService; ctx: RequestContext }
) {
  /** { identifier, request_id? } -> pending code / link. Same answer whether or not the account exists. */
  app.post("/auth/password/forgot", async (c) => {
    const body = await parseJsonBody(c, forgotPasswordBody);
    return c.json(await passwordReset.request(body.identifier, body.request_id, ctx.mail(c)));
  });

  /** { challengeId, code | token, password } -> { reset: true, continue? }. Signs the account out everywhere. */
  app.post("/auth/password/reset", async (c) => {
    const body = await parseJsonBody(c, resetPasswordBody);
    return c.json(await passwordReset.reset(body.challengeId, body.secret, body.password));
  });
}
