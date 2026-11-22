// /auth/master/*: master sign-in — password, then a code / link to the master's email, then a session token.

import { Controller, Post, type Ctx } from "../../common/kp/index.js";
import { bearerToken, type RequestContext } from "../http.js";
import { masterCodeBody, masterLoginBody, masterStatusBody } from "../schemas.js";
import type { MasterAuthService } from "./auth.js";

@Controller("/auth/master")
export class MasterController {
  constructor(
    private readonly masterAuth: MasterAuthService,
    private readonly http: RequestContext
  ) {}

  /** { username, password } -> { verify } (code or link sent to the master's email) */
  @Post("/login")
  async login(c: Ctx) {
    const { username, password } = await c.safeBody(masterLoginBody);
    return c.json(await this.masterAuth.login(username, password, this.http.mail(c)));
  }

  /** { challengeId, code } -> { access_token, expires_in } */
  @Post("/verify")
  async verify(c: Ctx) {
    c.header("Cache-Control", "no-store");
    const { challengeId, code } = await c.safeBody(masterCodeBody);
    return c.json(await this.masterAuth.verifyCode(challengeId, code));
  }

  /** { challengeId } -> { pending } | { access_token, ... } (link opened) */
  @Post("/status")
  async status(c: Ctx) {
    c.header("Cache-Control", "no-store");
    const { challengeId } = await c.safeBody(masterStatusBody);
    return c.json(await this.masterAuth.status(challengeId));
  }

  /** (Bearer master session) */
  @Post("/logout")
  async logout(c: Ctx) {
    await this.masterAuth.logout(bearerToken(c));
    return c.body(null, 204);
  }
}
