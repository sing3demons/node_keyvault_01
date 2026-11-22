// Forgot password: email a code / link (per the client's email_verification) to the account's address, then
// set a new password with it. A reset ends every session of the account (someone may know the old password)
// and tells the owner by email.
//
// The request step answers the same way whether or not the account exists, and never shows the address of an
// account looked up by username (only the masked address that was typed in).

import { HttpError } from "../../shared/http.js";
import type { AccountService } from "../accounts/service.js";
import type { ClientService } from "../clients/clients.js";
import { maskEmail, type EmailCodeService, type MailContext, type PendingVerification } from "../email/email-codes.js";
import type { OAuthService } from "../oauth/service.js";
import type { AuthRepository } from "../repository.js";

/** PendingVerification without the account's address unless the user typed it in. */
export type PendingReset = Omit<PendingVerification, "email"> & { email?: string };

export interface ResetDone {
  reset: true;
  /** The client's initiate_login_uri, to sign in again (when the reset started from its login page). */
  continue?: string;
}

export class PasswordResetService {
  constructor(
    private readonly repo: AuthRepository,
    private readonly oauth: OAuthService,
    private readonly accounts: AccountService,
    private readonly clients: ClientService,
    private readonly emailCodes: EmailCodeService
  ) {}

  /** `identifier`: username, or email when it contains "@" (already lowercased). */
  async request(identifier: string, requestId: string | undefined, mail: MailContext): Promise<PendingReset> {
    const client = requestId !== undefined ? await this.oauth.clientOf(await this.oauth.requireAuthRequest(requestId)) : undefined;
    const method = client?.emailVerification ?? "code";
    const byEmail = identifier.includes("@");
    const user = byEmail ? await this.repo.users.findByEmail(identifier) : await this.repo.users.findByUsername(identifier);
    const pending = user?.email
      ? await this.emailCodes.startOrResend(
          {
            purpose: "reset",
            reason: "reset_password",
            method,
            userId: user.id,
            email: user.email,
            ...(client ? { clientId: client.id } : {})
          },
          mail
        )
      : this.emailCodes.decoy({ reason: "reset_password", method, email: byEmail ? identifier : "" });
    const { email: _masked, ...rest } = pending;
    return byEmail ? { ...rest, email: maskEmail(identifier) } : rest;
  }

  async reset(challengeId: string, secret: string, password: string): Promise<ResetDone> {
    const challenge = await this.emailCodes.redeem(challengeId, secret, "reset");
    const userId = challenge.userId;
    if (!userId) throw new HttpError(400, "Code expired or not found — please request a new one", "expired_code");
    await this.accounts.setPassword(userId, password);
    // opening the email proved the address
    await this.repo.users.markEmailVerified(userId, challenge.email, new Date());
    await this.repo.tokens.revokeUser(userId);
    await this.emailCodes.notify(
      challenge.email,
      challenge.clientId,
      (app) => `Your ${app} password was changed`,
      [
        "The password of your account was just reset, and every device was signed out.",
        "",
        "If this was not you, reset your password again right away and check your passkeys and devices."
      ].join("\n")
    );
    const client = challenge.clientId ? await this.clients.find(challenge.clientId) : null;
    if (!client?.initiateLoginUri) return { reset: true };
    const url = new URL(client.initiateLoginUri);
    url.searchParams.set("iss", this.oauth.issuer);
    return { reset: true, continue: url.toString() };
  }
}
