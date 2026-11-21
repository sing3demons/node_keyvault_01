// Master credential sign-in (MASTER_CREDENTIALS): password, then a code or link sent to the master's email
// (MASTER_EMAIL_VERIFICATION, default otp), then a short-lived session token for the client-management API.
// Sessions are access-token rows of the reserved client MASTER_CLIENT_ID with scope "master" and no user.

import { randomToken, sha256 } from "../../shared/crypto.js";
import { HttpError } from "../../shared/http.js";
import { expiresIn } from "../../shared/util.js";
import type { ClientOwnerService } from "../clients/owners.js";
import type { EmailCodeService, MailContext, PendingVerification } from "../email/email-codes.js";
import type { MasterAccountStore } from "./account.js";
import { MASTER_CLIENT_ID, MASTER_SCOPE, type EmailVerificationMethod } from "../model.js";
import type { AuthRepository } from "../repository.js";

const SESSION_TTL_SEC = 60 * 60;

export interface MasterSession {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  username: string;
}

export class MasterAuthService {
  constructor(
    private readonly repo: AuthRepository,
    private readonly emailCodes: EmailCodeService,
    private readonly owners: ClientOwnerService,
    private readonly accounts: MasterAccountStore,
    /** MASTER_EMAIL_VERIFICATION */
    private readonly method: EmailVerificationMethod
  ) {}

  /** Step 1: username or email + password -> a code / link goes to the master's email. */
  async login(identifier: string, password: string, mail: MailContext): Promise<{ verify: PendingVerification }> {
    const account = await this.accounts.verify(identifier, password);
    if (!account) throw new HttpError(401, "Invalid master credentials", "access_denied");
    // only someone with the password learns that it was disabled
    await this.assertEnabled();
    const verify = await this.emailCodes.start(
      { purpose: "master", reason: "login", method: this.method, email: account.email },
      mail
    );
    return { verify };
  }

  /** Step 2 (code): the emailed code -> a session. */
  async verifyCode(challengeId: string, code: string): Promise<MasterSession> {
    await this.emailCodes.check(challengeId, code, undefined, ["master"]);
    return this.issue();
  }

  /** Step 2 (link): polled by /manage until the link was opened -> a session (once). */
  async status(challengeId: string): Promise<{ pending: true } | MasterSession> {
    return (await this.emailCodes.poll(challengeId, "master")) ? this.issue() : { pending: true };
  }

  /** For the admin middleware: is this Bearer token a live master session? */
  async session(accessToken: string): Promise<{ username: string } | null> {
    const token = await this.repo.tokens.findActiveAccess(sha256(accessToken), new Date());
    if (!token || token.clientId !== MASTER_CLIENT_ID || token.scope !== MASTER_SCOPE || token.userId) return null;
    const account = await this.accounts.get();
    return account && (await this.owners.masterEnabled()) ? { username: account.username } : null;
  }

  async logout(accessToken: string | undefined): Promise<void> {
    if (!accessToken) return;
    const token = await this.repo.tokens.findAccess(sha256(accessToken));
    if (token?.clientId === MASTER_CLIENT_ID) await this.repo.tokens.revokeFamily(token.familyId);
  }

  private async issue(): Promise<MasterSession> {
    await this.assertEnabled(); // it may have been disabled while the email was on its way
    const accessToken = randomToken();
    await this.repo.tokens.createPair(
      {
        id: sha256(accessToken),
        clientId: MASTER_CLIENT_ID,
        scope: MASTER_SCOPE,
        familyId: randomToken(16),
        expiresAt: expiresIn(SESSION_TTL_SEC * 1000)
      },
      null
    );
    const account = await this.accounts.get();
    return { access_token: accessToken, token_type: "Bearer", expires_in: SESSION_TTL_SEC, username: account?.username ?? "" };
  }

  private async assertEnabled(): Promise<void> {
    if (!(await this.owners.masterEnabled())) {
      throw new HttpError(401, "The master credential has been disabled — sign in as a client owner", "access_denied");
    }
  }
}
