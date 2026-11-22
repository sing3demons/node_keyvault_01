// The login page's endpoints: register, password and passkey sign-in, and the emailed code / link step.

import { deleteCookie, getCookie, setCookie, type Kp, type MiddlewareHandler } from "../../common/kp/index.js";
import { parseJsonBody } from "../../shared/http.js";
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

export function registerSignInRoutes(
  app: Kp,
  deps: {
    signIn: SignInService;
    oauth: OAuthService;
    webauthn: WebAuthnService;
    ctx: RequestContext;
    bearer: MiddlewareHandler;
  }
) {
  const { signIn, oauth, webauthn, ctx, bearer } = deps;

  /** Creates the account and emails a verification code / link. */
  app.post("/auth/register", async (c) => {
    const body = await parseJsonBody(c, registerBody);
    return c.json(await signIn.register(body, ctx.mail(c)), 201);
  });

  /** -> { redirect } | { verify } (enter the emailed code / open the link next) */
  app.post("/auth/login/password", async (c) => {
    const body = await parseJsonBody(c, passwordLoginBody);
    return c.json(await signIn.loginWithPassword(body.request_id, body.username, body.password, ctx.device(c), ctx.mail(c)));
  });

  // --- passkeys (username-less sign-in)
  app.post("/auth/webauthn/login/options", async (c) => {
    const body = await parseJsonBody(c, passkeyLoginOptionsBody);
    await oauth.requireAuthRequest(body.request_id);
    return c.json(await webauthn.loginOptions(body.request_id));
  });

  app.post("/auth/webauthn/login/verify", async (c) => {
    const body = await parseJsonBody(c, passkeyLoginVerifyBody);
    await oauth.requireAuthRequest(body.request_id);
    const userId = await webauthn.verifyLogin(body.challengeId, body.request_id, body.credential);
    return c.json(await oauth.completeAuthRequest(body.request_id, userId, { device: ctx.device(c), method: "passkey" }));
  });

  // --- emailed codes
  /** { challengeId, code, request_id? } -> { redirect } (sign-in) | { verified: true } */
  app.post("/auth/email/verify", async (c) => {
    const body = await parseJsonBody(c, emailCodeBody);
    const device = body.request_id !== undefined ? ctx.device(c) : undefined;
    return c.json(await signIn.confirmEmailCode(body.challengeId, body.code, body.request_id, device));
  });

  /** { challengeId } -> a fresh code / link is emailed */
  app.post("/auth/email/resend", async (c) => {
    const { challengeId } = await parseJsonBody(c, emailResendBody);
    return c.json(await signIn.resendEmailCode(challengeId, ctx.mail(c)));
  });

  // --- emailed links (clients with email_verification=link)
  /**
   * { challengeId, token, request_id? } -> { verified } | { redirect } | { continue: <client initiate_login_uri> }
   * (the link is then kept in a cookie for the login page of the request the client starts: .../resume).
   */
  app.post("/auth/email/link", async (c) => {
    const body = await parseJsonBody(c, emailLinkBody);
    const result = await signIn.openEmailLink(body.challengeId, body.token, ctx.device(c), body.request_id);
    if (!("continue" in result)) return c.json(result);
    const secure = isHttps(c);
    const { value, maxAgeSec } = result.resume;
    setCookie(c, EMAIL_LINK_COOKIE, value, { httpOnly: true, sameSite: "Lax", secure, path: "/auth", maxAge: maxAgeSec });
    setCookie(c, EMAIL_LINK_FLAG_COOKIE, "1", { sameSite: "Lax", secure, path: "/", maxAge: maxAgeSec });
    return c.json({ continue: result.continue });
  });

  /** { request_id } -> { redirect }: finish the sign-in the link started. */
  app.post("/auth/email/link/resume", async (c) => {
    const { request_id } = await parseJsonBody(c, emailLinkResumeBody);
    const cookie = getCookie(c, EMAIL_LINK_COOKIE);
    // single use either way
    deleteCookie(c, EMAIL_LINK_COOKIE, { path: "/auth" });
    deleteCookie(c, EMAIL_LINK_FLAG_COOKIE, { path: "/" });
    return c.json(await signIn.resumeEmailLink(cookie, request_id, ctx.device(c)));
  });

  /** { challengeId } (account page, verify link) -> { pending } | { verified } */
  app.post("/auth/email/status", async (c) => {
    c.header("Cache-Control", "no-store");
    const { challengeId } = await parseJsonBody(c, emailStatusBody);
    return c.json(await signIn.emailChallengeStatus(challengeId));
  });

  /** Account page (Bearer): email a code / link (per the token's client) to the current, unverified address. */
  app.post("/auth/me/email/verification", bearer, async (c) => {
    const user = c.get("user");
    return c.json(await signIn.startEmailVerification(user.id, user.clientId, ctx.mail(c)));
  });
}
