// The login page's flows: registration, password sign-in, and the emailed code / link step (per the
// client's email_verification), plus verifying an address from the account page. Each successful
// sign-in ends by completing the OAuth authorization request (OAuthService.completeAuthRequest).

import { HttpError } from "../../shared/http.js";
import { toAccount, type Account, type AccountService } from "../accounts/service.js";
import type { ClientService } from "../clients/clients.js";
import type { DeviceContext } from "../devices/devices.js";
import type { EmailCodeService, MailContext, PendingVerification } from "../email/email-codes.js";
import type { EmailChallenge } from "../model.js";
import type { OAuthService } from "../oauth/service.js";
import type { AuthRepository } from "../repository.js";
import type { RegisterBody } from "../schemas.js";

/** Result of a login step: signed in (go to `redirect`), or an emailed code must be entered first. */
export type SignInStep = { redirect: string } | { verify: PendingVerification };

/**
 * Opening a sign-in link when this browser has no sign-in of its own yet: go to the client's
 * initiate_login_uri (it starts one), carrying the link in a cookie (`resume`) for the login page.
 */
export interface LinkContinue {
  continue: string;
  resume: { value: string; maxAgeSec: number };
}

export class SignInService {
  constructor(
    private readonly repo: AuthRepository,
    private readonly oauth: OAuthService,
    private readonly accounts: AccountService,
    private readonly clients: ClientService,
    private readonly emailCodes: EmailCodeService
  ) {}

  // ---------------------------------------------------------------- registration, password

  /**
   * Creates the account (email unverified) and sends a code / link to it. With `request_id` (the login page)
   * confirming it also signs the user in; without it (API clients) it only verifies the address.
   */
  async register(body: RegisterBody, mail: MailContext): Promise<Account & { verification: PendingVerification }> {
    const { request_id: requestId, ...fields } = body;
    const client = requestId !== undefined ? await this.oauth.clientOf(await this.oauth.requireAuthRequest(requestId)) : undefined;
    const user = await this.accounts.create(fields);
    const verification = await this.emailCodes.start(
      {
        purpose: requestId !== undefined ? "signin" : "verify",
        reason: "register",
        // the client's choice; API registration without a client gets a code
        method: client?.emailVerification ?? "code",
        userId: user.id,
        email: fields.email,
        ...(requestId !== undefined ? { authRequestId: requestId } : {}),
        ...(client ? { clientId: client.id } : {})
      },
      mail
    );
    return { ...toAccount(user), verification };
  }

  /**
   * Password step. Signing in with an email address always needs the code / link emailed to it;
   * with a username, only while the account's email is still unverified (finishing registration).
   */
  async loginWithPassword(
    requestId: string,
    identifier: string,
    password: string,
    device: DeviceContext,
    mail: MailContext
  ): Promise<SignInStep> {
    const client = await this.oauth.clientOf(await this.oauth.requireAuthRequest(requestId));
    const user = await this.accounts.verifyPassword(identifier, password);
    const byEmail = identifier.includes("@");
    if (user.email && (byEmail || !user.emailVerifiedAt)) {
      const verify = await this.emailCodes.start(
        {
          purpose: "signin",
          reason: byEmail ? "login" : "verify_email",
          method: client.emailVerification,
          userId: user.id,
          email: user.email,
          authRequestId: requestId,
          clientId: client.id
        },
        mail
      );
      return { verify };
    }
    return this.oauth.completeAuthRequest(requestId, user.id, { device, method: "password" });
  }

  // ---------------------------------------------------------------- emailed codes

  /** Account page: email a code / link (per the caller's client) to the user's current, unverified address. */
  async startEmailVerification(userId: string, clientId: string, mail: MailContext): Promise<PendingVerification> {
    const user = await this.accounts.require(userId);
    if (!user.email) throw new HttpError(400, "Add an email address first");
    if (user.emailVerifiedAt) throw new HttpError(409, "Email is already verified", "conflict");
    const client = await this.clients.find(clientId);
    return this.emailCodes.start(
      {
        purpose: "verify",
        reason: "verify_email",
        method: client?.emailVerification ?? "code",
        userId: user.id,
        email: user.email,
        ...(client ? { clientId: client.id } : {})
      },
      mail
    );
  }

  resendEmailCode(challengeId: string, mail: MailContext): Promise<PendingVerification> {
    return this.emailCodes.resend(challengeId, mail);
  }

  /**
   * Confirms an emailed code: the address is marked verified, and a sign-in challenge also completes its
   * authorization request (`requestId` and `device` are required for those).
   */
  async confirmEmailCode(
    challengeId: string,
    code: string,
    requestId?: string,
    device?: DeviceContext
  ): Promise<{ redirect: string } | { verified: true }> {
    if (requestId !== undefined) await this.oauth.requireAuthRequest(requestId);
    const challenge = await this.emailCodes.check(challengeId, code, requestId);
    await this.markVerified(challenge);
    if (challenge.purpose === "verify") return { verified: true };
    if (requestId === undefined || !device) throw new HttpError(400, "request_id is required for this code");
    return this.oauth.completeAuthRequest(requestId, challenge.userId!, {
      device,
      method: challenge.reason === "register" ? "registration" : "password+email_code"
    });
  }

  // ---------------------------------------------------------------- emailed links

  /**
   * Emailed link opened (marks the address verified).
   * - verify link -> { verified }
   * - sign-in link with `requestId` (an authorization request this browser started for the same client)
   *   -> signed in on it: { redirect } to the client's redirect_uri with a code
   * - sign-in link without one -> { continue } to the client's initiate_login_uri (OIDC Core §4), which starts
   *   that request; the link rides along in a cookie (resumeEmailLink). A client without initiate_login_uri
   *   gets its original request completed here instead (fine for clients that keep their state in cookies).
   */
  async openEmailLink(
    challengeId: string,
    token: string,
    device: DeviceContext,
    requestId?: string
  ): Promise<{ redirect: string } | { verified: true } | LinkContinue> {
    if (requestId !== undefined) {
      const req = await this.oauth.requireAuthRequest(requestId);
      const challenge = await this.emailCodes.openLink(challengeId, token, req.clientId);
      return this.signInWithLink(challenge, requestId, device);
    }
    const challenge = await this.emailCodes.inspectLink(challengeId, token);
    await this.markVerified(challenge);
    // verify link: done; master link: approved, the /manage page waiting for it picks the sign-in up
    if (challenge.purpose === "verify" || challenge.purpose === "master") return { verified: true };

    const client = challenge.clientId ? await this.clients.find(challenge.clientId) : null;
    if (client?.initiateLoginUri) {
      const url = new URL(client.initiateLoginUri);
      url.searchParams.set("iss", this.oauth.issuer);
      return {
        continue: url.toString(),
        resume: {
          value: `${challengeId}.${token}`,
          maxAgeSec: Math.max(1, Math.floor((challenge.expiresAt.getTime() - Date.now()) / 1000))
        }
      };
    }
    const original = challenge.authRequestId ? await this.oauth.findAuthRequest(challenge.authRequestId) : null;
    if (!original) {
      throw new HttpError(400, "This sign-in has expired — please sign in again from the app", "expired_code");
    }
    const consumed = await this.emailCodes.openLink(challengeId, token, original.clientId);
    return this.signInWithLink(consumed, original.id, device);
  }

  /** Login page of a sign-in started by the client's initiate_login_uri: redeem the link kept in the cookie. */
  async resumeEmailLink(cookie: string | undefined, requestId: string, device: DeviceContext): Promise<{ redirect: string }> {
    const [challengeId, token] = (cookie ?? "").split(".");
    if (!challengeId || !token) {
      throw new HttpError(400, "No sign-in link to continue — open the link from the email again", "expired_code");
    }
    const r = await this.openEmailLink(challengeId, token, device, requestId);
    if (!("redirect" in r)) throw new HttpError(400, "This link does not sign in");
    return r;
  }

  /** Account page, verify-only link: `{ pending: true }` until it has been opened. */
  async emailChallengeStatus(challengeId: string): Promise<{ pending: true } | { verified: true }> {
    return (await this.emailCodes.poll(challengeId)) ? { verified: true } : { pending: true };
  }

  // ---------------------------------------------------------------- helpers

  private async markVerified(challenge: EmailChallenge): Promise<void> {
    if (challenge.userId) await this.repo.users.markEmailVerified(challenge.userId, challenge.email, new Date());
  }

  private async signInWithLink(challenge: EmailChallenge, requestId: string, device: DeviceContext) {
    await this.markVerified(challenge);
    return this.oauth.completeAuthRequest(requestId, challenge.userId!, {
      device,
      method: challenge.reason === "register" ? "registration" : "password+email_link"
    });
  }
}
