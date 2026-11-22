// /auth/password/*: forgot password (no sign-in needed) · /auth/me/password: change it while signed in.

import { Controller, Post, UseInterceptors, type Ctx } from "../../common/kp/index.js";
import { Bearer } from "../../shared/middleware.js";
import type { RequestContext } from "../http.js";
import { changePasswordBody, forgotPasswordBody, resetPasswordBody } from "../schemas.js";
import type { PasswordService } from "./service.js";

@Controller("/auth")
export class PasswordController {
  constructor(
    private readonly passwords: PasswordService,
    private readonly http: RequestContext
  ) {}

  /** { identifier, request_id? } -> pending code / link. Same answer whether or not the account exists. */
  @Post("/password/forgot")
  async forgot(c: Ctx) {
    const body = await c.safeBody(forgotPasswordBody);
    return c.json(await this.passwords.requestReset(body.identifier, body.request_id, this.http.mail(c)));
  }

  /** { challengeId, code | token, password } -> { reset: true, continue? }. Signs the account out everywhere. */
  @Post("/password/reset")
  async reset(c: Ctx) {
    const body = await c.safeBody(resetPasswordBody);
    return c.json(await this.passwords.reset(body.challengeId, body.secret, body.password));
  }

  /** { currentPassword, newPassword, signOutOthers? = true } -> { changed, signedOutOthers }. This session stays signed in. */
  @Post("/me/password")
  @UseInterceptors(Bearer)
  async change(c: Ctx) {
    const user = c.get("user");
    const body = await c.safeBody(changePasswordBody);
    return c.json(
      await this.passwords.change(
        { userId: user.id, clientId: user.clientId, ...(user.familyId !== undefined ? { familyId: user.familyId } : {}) },
        body.currentPassword,
        body.newPassword,
        body.signOutOthers
      )
    );
  }
}
