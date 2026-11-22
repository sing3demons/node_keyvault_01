// /auth/password/*: forgot password (no sign-in needed) · /auth/me/password: change it while signed in.

import type { Kp, MiddlewareHandler } from "../../common/kp/index.js";
import { parseJsonBody } from "../../shared/http.js";
import type { RequestContext } from "../http.js";
import { changePasswordBody, forgotPasswordBody, resetPasswordBody } from "../schemas.js";
import type { PasswordService } from "./service.js";

export function registerPasswordRoutes(
  app: Kp,
  { passwords, ctx, bearer }: { passwords: PasswordService; ctx: RequestContext; bearer: MiddlewareHandler }
) {
  /** { identifier, request_id? } -> pending code / link. Same answer whether or not the account exists. */
  app.post("/auth/password/forgot", async (c) => {
    const body = await parseJsonBody(c, forgotPasswordBody);
    return c.json(await passwords.requestReset(body.identifier, body.request_id, ctx.mail(c)));
  });

  /** { challengeId, code | token, password } -> { reset: true, continue? }. Signs the account out everywhere. */
  app.post("/auth/password/reset", async (c) => {
    const body = await parseJsonBody(c, resetPasswordBody);
    return c.json(await passwords.reset(body.challengeId, body.secret, body.password));
  });

  /** { currentPassword, newPassword, signOutOthers? = true } -> { changed, signedOutOthers }. This session stays signed in. */
  app.post("/auth/me/password", bearer, async (c) => {
    const user = c.get("user");
    const body = await parseJsonBody(c, changePasswordBody);
    return c.json(
      await passwords.change(
        { userId: user.id, clientId: user.clientId, ...(user.familyId !== undefined ? { familyId: user.familyId } : {}) },
        body.currentPassword,
        body.newPassword,
        body.signOutOthers
      )
    );
  });
}
