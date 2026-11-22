// The login page's endpoints: register, password and passkey sign-in, and the emailed code / link step.

import { Controller, Post, UseInterceptors, deleteCookie, getCookie, setCookie, type Ctx } from "../../common/kp/index.js";
import { Bearer } from "../../shared/middleware.js";
import { isHttps, type RequestContext } from "../http.js";
import type { OAuthService } from "../oauth/service.js";
import {
  emailCodeBody,
  emailLinkBody,
  emailLinkResumeBody,
  emailResendBody,
  emailStatusBody,
  passkeyLoginOptionsBody,
  passkeyLoginVerifyBody,
  passwordLoginBody,
  registerBody
} from "../schemas.js";
import type { WebAuthnService } from "../webauthn/webauthn.js";
import type { SignInService } from "./service.js";

/** An opened sign-in link waiting for the client's fresh authorization request (httpOnly, /auth only). */
const EMAIL_LINK_COOKIE = "kv_email_link";
/** Readable flag so the login page knows to ask for it (carries nothing secret). */
const EMAIL_LINK_FLAG_COOKIE = "kv_email_link_pending";

@Controller("/auth")
export class SignInController {
  constructor(
    private readonly signIn: SignInService,
    private readonly oauth: OAuthService,
    private readonly webauthn: WebAuthnService,
    private readonly http: RequestContext
  ) {}

  /** Creates the account and emails a verification code / link. */
  @Post("/register")
  async register(c: Ctx) {
    const body = await c.safeBody(registerBody);
    return c.json(await this.signIn.register(body, this.http.mail(c)), 201);
  }

  /** -> { redirect } | { verify } (enter the emailed code / open the link next) */
  @Post("/login/password")
  async loginWithPassword(c: Ctx) {
    const body = await c.safeBody(passwordLoginBody);
    return c.json(
      await this.signIn.loginWithPassword(body.request_id, body.username, body.password, this.http.device(c), this.http.mail(c))
    );
  }

  // --- passkeys (username-less sign-in)

  @Post("/webauthn/login/options")
  async passkeyOptions(c: Ctx) {
    const body = await c.safeBody(passkeyLoginOptionsBody);
    await this.oauth.requireAuthRequest(body.request_id);
    return c.json(await this.webauthn.loginOptions(body.request_id));
  }

  @Post("/webauthn/login/verify")
  async passkeyVerify(c: Ctx) {
    const body = await c.safeBody(passkeyLoginVerifyBody);
    await this.oauth.requireAuthRequest(body.request_id);
    const userId = await this.webauthn.verifyLogin(body.challengeId, body.request_id, body.credential);
    return c.json(await this.oauth.completeAuthRequest(body.request_id, userId, { device: this.http.device(c), method: "passkey" }));
  }

  // --- emailed codes

  /** { challengeId, code, request_id? } -> { redirect } (sign-in) | { verified: true } */
  @Post("/email/verify")
  async verifyEmailCode(c: Ctx) {
    const body = await c.safeBody(emailCodeBody);
    const device = body.request_id !== undefined ? this.http.device(c) : undefined;
    return c.json(await this.signIn.confirmEmailCode(body.challengeId, body.code, body.request_id, device));
  }

  /** { challengeId } -> a fresh code / link is emailed */
  @Post("/email/resend")
  async resendEmailCode(c: Ctx) {
    const { challengeId } = await c.safeBody(emailResendBody);
    return c.json(await this.signIn.resendEmailCode(challengeId, this.http.mail(c)));
  }

  // --- emailed links (clients with email_verification=link)

  /**
   * { challengeId, token, request_id? } -> { verified } | { redirect } | { continue: <client initiate_login_uri> }
   * (the link is then kept in a cookie for the login page of the request the client starts: .../resume).
   */
  @Post("/email/link")
  async openEmailLink(c: Ctx) {
    const body = await c.safeBody(emailLinkBody);
    const result = await this.signIn.openEmailLink(body.challengeId, body.token, this.http.device(c), body.request_id);
    if (!("continue" in result)) return c.json(result);
    const secure = isHttps(c);
    const { value, maxAgeSec } = result.resume;
    setCookie(c, EMAIL_LINK_COOKIE, value, { httpOnly: true, sameSite: "Lax", secure, path: "/auth", maxAge: maxAgeSec });
    setCookie(c, EMAIL_LINK_FLAG_COOKIE, "1", { sameSite: "Lax", secure, path: "/", maxAge: maxAgeSec });
    return c.json({ continue: result.continue });
  }

  /** { request_id } -> { redirect }: finish the sign-in the link started. */
  @Post("/email/link/resume")
  async resumeEmailLink(c: Ctx) {
    const { request_id } = await c.safeBody(emailLinkResumeBody);
    const cookie = getCookie(c, EMAIL_LINK_COOKIE);
    // single use either way
    deleteCookie(c, EMAIL_LINK_COOKIE, { path: "/auth" });
    deleteCookie(c, EMAIL_LINK_FLAG_COOKIE, { path: "/" });
    return c.json(await this.signIn.resumeEmailLink(cookie, request_id, this.http.device(c)));
  }

  /** { challengeId } (account page, verify link) -> { pending } | { verified } */
  @Post("/email/status")
  async emailStatus(c: Ctx) {
    c.header("Cache-Control", "no-store");
    const { challengeId } = await c.safeBody(emailStatusBody);
    return c.json(await this.signIn.emailChallengeStatus(challengeId));
  }

  /** Account page (Bearer): email a code / link (per the token's client) to the current, unverified address. */
  @Post("/me/email/verification")
  @UseInterceptors(Bearer)
  async startEmailVerification(c: Ctx) {
    const user = c.get("user");
    return c.json(await this.signIn.startEmailVerification(user.id, user.clientId, this.http.mail(c)));
  }
}
