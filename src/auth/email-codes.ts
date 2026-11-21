// One-time codes sent by email: proving an address (registration, account page) and the extra
// sign-in step when someone signs in with their email address.

import { randomInt, timingSafeEqual } from "node:crypto";
import { randomToken, sha256 } from "../shared/crypto.js";
import { HttpError } from "../shared/http.js";
import type { Mailer } from "../shared/mail.js";
import { errorMessage, expiresIn } from "../shared/util.js";
import type { EmailChallenge, EmailChallengePurpose, EmailChallengeReason } from "./model.js";
import type { AuthRepository } from "./repository.js";

export interface EmailCodeSettings {
  ttlSec: number;
  /** Wrong codes allowed before the challenge is thrown away. */
  maxAttempts: number;
  resendCooldownSec: number;
  /** First send + resends. */
  maxSends: number;
  /** Product name used in the emails. */
  appName: string;
}

/** What the client gets back while a code is pending (never the code itself). */
export interface PendingVerification {
  challengeId: string;
  /** Masked, e.g. "s•••s@example.com". */
  email: string;
  reason: EmailChallengeReason;
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
    private readonly settings: EmailCodeSettings
  ) {}

  /** Creates a challenge and emails its code. */
  async start(p: {
    purpose: EmailChallengePurpose;
    reason: EmailChallengeReason;
    userId: string;
    email: string;
    authRequestId?: string;
  }): Promise<PendingVerification> {
    const id = randomToken(24);
    const code = this.newCode();
    const now = new Date();
    const challenge: EmailChallenge = {
      id,
      purpose: p.purpose,
      reason: p.reason,
      userId: p.userId,
      email: p.email,
      codeHash: this.hash(id, code),
      attempts: 0,
      sends: 1,
      sentAt: now,
      ...(p.authRequestId !== undefined ? { authRequestId: p.authRequestId } : {}),
      expiresAt: expiresIn(this.settings.ttlSec * 1000)
    };
    await this.repo.emailChallenges.create(challenge);
    await this.deliver(challenge, code, true);
    return this.pending(challenge);
  }

  /** Emails a fresh code for the same challenge (the old code stops working). */
  async resend(challengeId: string): Promise<PendingVerification> {
    const now = new Date();
    const stored = await this.repo.emailChallenges.findActive(challengeId, now);
    if (!stored) throw this.gone();
    const wait = Math.ceil((this.resendAt(stored).getTime() - now.getTime()) / 1000);
    if (wait > 0) throw new HttpError(429, `Please wait ${wait}s before requesting another code`, "slow_down");
    if (stored.sends >= this.settings.maxSends) {
      throw new HttpError(429, "Too many codes requested — please start again", "slow_down");
    }
    const code = this.newCode();
    const next: EmailChallenge = {
      ...stored,
      codeHash: this.hash(stored.id, code),
      attempts: 0,
      sends: stored.sends + 1,
      sentAt: now,
      expiresAt: expiresIn(this.settings.ttlSec * 1000)
    };
    await this.repo.emailChallenges.replaceCode(next.id, next.codeHash, next.sentAt, next.expiresAt);
    await this.deliver(next, code, false);
    return this.pending(next);
  }

  /**
   * Checks a code and consumes the challenge on success. `authRequestId` must match what the challenge
   * was created for (a sign-in code cannot be used outside its login page, and vice versa).
   */
  async check(challengeId: string, code: string, authRequestId?: string): Promise<EmailChallenge> {
    const stored = await this.repo.emailChallenges.findActive(challengeId, new Date());
    if (!stored || (stored.authRequestId ?? null) !== (authRequestId ?? null)) throw this.gone();
    if (!this.matches(stored, code)) {
      const attempts = await this.repo.emailChallenges.recordFailedAttempt(stored.id);
      const left = this.settings.maxAttempts - (attempts ?? this.settings.maxAttempts);
      if (left <= 0) {
        await this.repo.emailChallenges.consume(stored.id);
        throw new HttpError(400, "Too many wrong codes — please start again", "invalid_code");
      }
      throw new HttpError(400, `Wrong code — ${left} attempt${left === 1 ? "" : "s"} left`, "invalid_code");
    }
    // single use: of two concurrent correct submissions only one gets through
    if (!(await this.repo.emailChallenges.consume(stored.id))) throw this.gone();
    return stored;
  }

  // ---------------------------------------------------------------- helpers

  private newCode(): string {
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
      expiresAt: c.expiresAt.toISOString(),
      resendAt: this.resendAt(c).toISOString()
    };
  }

  private gone(): HttpError {
    return new HttpError(400, "Code expired or not found — please request a new one", "expired_code");
  }

  /** Sends the code. If the very first send fails the challenge is removed, since nobody can complete it. */
  private async deliver(c: EmailChallenge, code: string, first: boolean): Promise<void> {
    const { appName, ttlSec } = this.settings;
    const minutes = Math.round(ttlSec / 60);
    const action = {
      register: "confirm your email address and finish creating your account",
      verify_email: "confirm your email address",
      login: "finish signing in"
    }[c.reason];
    const subject = c.reason === "login" ? `${appName} sign-in code: ${code}` : `${appName} verification code: ${code}`;
    const text = [
      `Your ${appName} code is: ${code}`,
      "",
      `Enter it to ${action}. It expires in ${minutes} minute${minutes === 1 ? "" : "s"}.`,
      "",
      "If you did not request this, you can ignore this email" +
        (c.reason === "login" ? " — but someone knows your password, so please change it." : ".")
    ].join("\n");
    const html =
      `<p>Your ${escapeHtml(appName)} code is:</p>` +
      `<p style="font-size:28px;font-weight:700;letter-spacing:6px;font-family:monospace">${code}</p>` +
      `<p>Enter it to ${action}. It expires in ${minutes} minute${minutes === 1 ? "" : "s"}.</p>` +
      `<p style="color:#666">If you did not request this, you can ignore this email` +
      (c.reason === "login" ? " — but someone knows your password, so please change it." : ".") +
      `</p>`;
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
