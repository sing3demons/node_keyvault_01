// One-time codes or links sent by email: proving an address (registration, account page) and the extra
// sign-in step when someone signs in with their email address.
//
// The method is chosen per OAuth client (OAuthClient.emailVerification) and fixed on the challenge:
// "code" — the email holds a 6-digit code, typed into the page that asked for it (check()).
// "link" — the email holds a link with a 256-bit token:
//   - sign-in links sign the user in where the link is opened: the client starts a fresh authorization
//     request there (OIDC initiate_login_uri) and the link is redeemed on it (inspectLink() then openLink());
//   - verify-only links mark the address verified; the account page that asked notices by polling (poll()).

import { randomInt, timingSafeEqual } from "node:crypto";
import { randomToken, sha256 } from "../shared/crypto.js";
import { HttpError } from "../shared/http.js";
import type { Mailer } from "../shared/mail.js";
import { errorMessage, expiresIn } from "../shared/util.js";
import type { EmailChallenge, EmailChallengePurpose, EmailChallengeReason, EmailVerificationMethod } from "./model.js";
import type { AuthRepository } from "./repository.js";

export interface EmailCodeSettings {
  ttlSec: number;
  /** Wrong codes allowed before the challenge is thrown away. */
  maxAttempts: number;
  resendCooldownSec: number;
  /** First send + resends. */
  maxSends: number;
  /** Product name used in emails not tied to a client (else the client's name). */
  appName: string;
}

/** Per-request bits of an email: which auth UI origin its links open. */
export interface MailContext {
  /** Origin of the login / account page making the request (allow-listed by the controller). */
  uiOrigin: string;
}

/** What the client gets back while a code is pending (never the code itself). */
export interface PendingVerification {
  challengeId: string;
  /** Masked, e.g. "s•••s@example.com". */
  email: string;
  reason: EmailChallengeReason;
  /** "code": ask for the 6 digits; "link": tell the user to open the email and poll the status. */
  method: EmailVerificationMethod;
  expiresAt: string;
  /** Earliest time a resend is accepted. */
  resendAt: string;
}

const CODE_DIGITS = 6;

/** "someone@example.com" -> "s•••e@example.com" */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf("@");
  if (at < 1) return email;
  const local = email.slice(0, at);
  const shown = local.length <= 2 ? local[0] + "•" : `${local[0]}•••${local[local.length - 1]}`;
  return shown + email.slice(at);
}

export class EmailCodeService {
  constructor(
    private readonly repo: AuthRepository,
    private readonly mailer: Mailer,
    private readonly settings: EmailCodeSettings,
    /** client_name for emails sent on behalf of a client. */
    private readonly clientName: (clientId: string) => Promise<string | undefined>
  ) {}

  /** Creates a challenge and emails its code / link. */
  async start(
    p: {
      purpose: EmailChallengePurpose;
      reason: EmailChallengeReason;
      method: EmailVerificationMethod;
      userId?: string;
      email: string;
      authRequestId?: string;
      clientId?: string;
    },
    mail: MailContext
  ): Promise<PendingVerification> {
    const id = randomToken(24);
    const method = p.method;
    const code = this.newSecret(method);
    const now = new Date();
    const challenge: EmailChallenge = {
      id,
      purpose: p.purpose,
      reason: p.reason,
      method,
      ...(p.userId !== undefined ? { userId: p.userId } : {}),
      email: p.email,
      codeHash: this.hash(id, code),
      attempts: 0,
      sends: 1,
      sentAt: now,
      ...(p.authRequestId !== undefined ? { authRequestId: p.authRequestId } : {}),
      ...(p.clientId !== undefined ? { clientId: p.clientId } : {}),
      expiresAt: expiresIn(this.settings.ttlSec * 1000)
    };
    await this.repo.emailChallenges.create(challenge);
    await this.deliver(challenge, code, true, mail);
    return this.pending(challenge);
  }

  /** Emails a fresh code for the same challenge (the old code stops working). */
  async resend(challengeId: string, mail: MailContext): Promise<PendingVerification> {
    const now = new Date();
    const stored = await this.repo.emailChallenges.findActive(challengeId, now);
    if (!stored) throw this.gone();
    const wait = Math.ceil((this.resendAt(stored).getTime() - now.getTime()) / 1000);
    if (wait > 0) throw new HttpError(429, `Please wait ${wait}s before requesting another code`, "slow_down");
    if (stored.sends >= this.settings.maxSends) {
      throw new HttpError(429, "Too many codes requested — please start again", "slow_down");
    }
    const code = this.newSecret(this.methodOf(stored));
    const next: EmailChallenge = {
      ...stored,
      codeHash: this.hash(stored.id, code),
      attempts: 0,
      sends: stored.sends + 1,
      sentAt: now,
      expiresAt: expiresIn(this.settings.ttlSec * 1000)
    };
    await this.repo.emailChallenges.replaceCode(next.id, next.codeHash, next.sentAt, next.expiresAt);
    await this.deliver(next, code, false, mail);
    return this.pending(next);
  }

  /**
   * Checks a code and consumes the challenge on success. `authRequestId` must match what the challenge
   * was created for (a sign-in code cannot be used outside its login page, and vice versa).
   */
  async check(
    challengeId: string,
    code: string,
    authRequestId?: string,
    /** Which kinds this endpoint may consume (master codes only via the master sign-in, and vice versa). */
    purposes: readonly EmailChallengePurpose[] = ["signin", "verify"]
  ): Promise<EmailChallenge> {
    const stored = await this.repo.emailChallenges.findActive(challengeId, new Date());
    if (!stored || !purposes.includes(stored.purpose) || (stored.authRequestId ?? null) !== (authRequestId ?? null)) {
      throw this.gone();
    }
    if (this.methodOf(stored) !== "code") throw new HttpError(400, "Open the link in the email instead", "invalid_code");
    await this.verifySecret(stored, code);
    // single use: of two concurrent correct submissions only one gets through
    if (!(await this.repo.emailChallenges.consume(stored.id))) throw this.gone();
    return stored;
  }

  /**
   * Emailed link opened and confirmed (the person proved they can read the mailbox).
   * - "signin": consumed and returned, for the caller to sign the user in on `signInClientId`'s authorization
   *   request in the browser that opened the link. Bound to the token and the client, not to the original
   *   request: the password (or registration) was already checked when the link was sent.
   * - "verify": marked approved (kept for the account page's poll()); opening it twice is harmless.
   */
  async openLink(challengeId: string, token: string, signInClientId?: string): Promise<EmailChallenge> {
    const stored = await this.findLink(challengeId);
    if (stored.purpose === "signin") {
      if (signInClientId === undefined) throw new HttpError(400, "request_id is required for a sign-in link");
      if (stored.clientId !== undefined && stored.clientId !== signInClientId) {
        throw new HttpError(400, "This link signs in to a different app", "invalid_request");
      }
      await this.verifySecret(stored, token);
      if (!(await this.repo.emailChallenges.consume(stored.id))) throw this.gone();
      return stored;
    }
    return this.approve(stored, token);
  }

  /**
   * Link page, before any sign-in exists in this browser: checks the token without using it up
   * (sign-in links), so the page can send the browser to the client to start one. Verify links are
   * approved right away.
   */
  async inspectLink(challengeId: string, token: string): Promise<EmailChallenge> {
    const stored = await this.findLink(challengeId);
    // verify / master: approve now; the page waiting for it notices (poll)
    if (stored.purpose !== "signin") return this.approve(stored, token);
    await this.verifySecret(stored, token);
    return stored;
  }

  private async findLink(challengeId: string): Promise<EmailChallenge> {
    const stored = await this.repo.emailChallenges.findActive(challengeId, new Date());
    if (!stored || this.methodOf(stored) !== "link") throw this.gone();
    return stored;
  }

  private async approve(stored: EmailChallenge, token: string): Promise<EmailChallenge> {
    if (stored.approvedAt) return stored; // opened twice: already done
    await this.verifySecret(stored, token);
    if (!(await this.repo.emailChallenges.approve(stored.id, new Date()))) throw this.gone();
    return { ...stored, approvedAt: new Date() };
  }

  /**
   * Account page: has the verify-only link been opened? Null while waiting; once approved the challenge is
   * consumed and returned. (Sign-in challenges are not polled: their link signs in where it is opened.)
   */
  async poll(challengeId: string, purpose: "verify" | "master" = "verify"): Promise<EmailChallenge | null> {
    const stored = await this.repo.emailChallenges.findActive(challengeId, new Date());
    if (!stored || stored.purpose !== purpose) throw this.gone();
    if (!stored.approvedAt) return null;
    if (!(await this.repo.emailChallenges.consume(stored.id))) throw this.gone();
    return stored;
  }

  // ---------------------------------------------------------------- helpers

  /** Wrong secrets count against the challenge; too many and it is thrown away. */
  private async verifySecret(stored: EmailChallenge, secret: string): Promise<void> {
    if (!this.matches(stored, secret)) {
      const attempts = await this.repo.emailChallenges.recordFailedAttempt(stored.id);
      const left = this.settings.maxAttempts - (attempts ?? this.settings.maxAttempts);
      if (left <= 0) {
        await this.repo.emailChallenges.consume(stored.id);
        throw new HttpError(400, "Too many wrong codes — please start again", "invalid_code");
      }
      throw new HttpError(
        400,
        this.methodOf(stored) === "link"
          ? "This link is invalid or was replaced by a newer email"
          : `Wrong code — ${left} attempt${left === 1 ? "" : "s"} left`,
        "invalid_code"
      );
    }
  }

  /** Challenges stored before links existed have no method. */
  private methodOf(c: EmailChallenge): EmailVerificationMethod {
    return c.method ?? "code";
  }

  /** 6 digits to type, or a 256-bit token for a link. */
  private newSecret(method: EmailVerificationMethod): string {
    if (method === "link") return randomToken();
    return randomInt(0, 10 ** CODE_DIGITS)
      .toString()
      .padStart(CODE_DIGITS, "0");
  }

  /** Bound to the challenge id, so equal codes of different challenges hash differently. */
  private hash(challengeId: string, code: string): string {
    return sha256(`${challengeId}:${code}`);
  }

  private matches(stored: EmailChallenge, code: string): boolean {
    const given = Buffer.from(this.hash(stored.id, code.trim()));
    const expected = Buffer.from(stored.codeHash);
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  private resendAt(c: EmailChallenge): Date {
    return new Date(c.sentAt.getTime() + this.settings.resendCooldownSec * 1000);
  }

  private pending(c: EmailChallenge): PendingVerification {
    return {
      challengeId: c.id,
      email: maskEmail(c.email),
      reason: c.reason,
      method: this.methodOf(c),
      expiresAt: c.expiresAt.toISOString(),
      resendAt: this.resendAt(c).toISOString()
    };
  }

  private gone(): HttpError {
    return new HttpError(400, "Code expired or not found — please request a new one", "expired_code");
  }

  /** Sends the code / link. If the very first send fails the challenge is removed, since nobody can complete it. */
  private async deliver(c: EmailChallenge, secret: string, first: boolean, mail: MailContext): Promise<void> {
    const { ttlSec } = this.settings;
    const baseName = (c.clientId && (await this.clientName(c.clientId).catch(() => undefined))) || this.settings.appName;
    const appName = c.purpose === "master" ? `${baseName} master` : baseName;
    const minutes = Math.round(ttlSec / 60);
    const expires = `It expires in ${minutes} minute${minutes === 1 ? "" : "s"}.`;
    const action = {
      register: "confirm your email address and finish creating your account",
      verify_email: "confirm your email address",
      login: "finish signing in"
    }[c.reason];
    const ignore =
      "If you did not request this, you can ignore this email" +
      (c.reason === "login" ? " — but someone knows your password, so please change it." : ".");
    const name = escapeHtml(appName);
    let subject: string, text: string, html: string;
    if (this.methodOf(c) === "link") {
      const params = new URLSearchParams({ id: c.id, token: secret });
      if (c.purpose === "signin") params.set("signin", "1"); // tells the page to start a sign-in first
      if (c.purpose === "master") params.set("master", "1"); // approves a master sign-in waiting elsewhere
      const url = `${mail.uiOrigin}/verify-email?${params}`;
      subject = c.reason === "login" ? `Sign in to ${appName}` : `Confirm your email for ${appName}`;
      text = [`Open this link to ${action}:`, "", url, "", expires, "", ignore].join("\n");
      html =
        `<p>Open this link to ${action}:</p>` +
        `<p><a href="${escapeHtml(url)}" style="display:inline-block;padding:10px 18px;border-radius:8px;` +
        `background:#4f46e5;color:#fff;text-decoration:none;font-weight:600">` +
        `${c.reason === "login" ? "Sign in" : "Confirm email"}</a></p>` +
        `<p style="color:#666;font-size:13px">Or paste this address into your browser:<br>${escapeHtml(url)}</p>` +
        `<p>${expires}</p><p style="color:#666">${ignore}</p>`;
    } else {
      subject = c.reason === "login" ? `${appName} sign-in code: ${secret}` : `${appName} verification code: ${secret}`;
      text = [`Your ${appName} code is: ${secret}`, "", `Enter it to ${action}. ${expires}`, "", ignore].join("\n");
      html =
        `<p>Your ${name} code is:</p>` +
        `<p style="font-size:28px;font-weight:700;letter-spacing:6px;font-family:monospace">${secret}</p>` +
        `<p>Enter it to ${action}. ${expires}</p><p style="color:#666">${ignore}</p>`;
    }
    try {
      await this.mailer.send({ to: c.email, subject, text, html });
    } catch (error) {
      console.error("sending email failed", errorMessage(error));
      if (first) await this.repo.emailChallenges.consume(c.id).catch(() => {});
      throw new HttpError(503, "Could not send the email — please try again later", "temporarily_unavailable");
    }
  }
}

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
