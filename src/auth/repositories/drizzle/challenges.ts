// Short-lived challenges: WebAuthn (passkey) challenges and emailed codes / links.

import { and, desc, eq, gt, lt, sql } from "drizzle-orm";
import type { EmailChallenge, WebAuthnChallenge } from "../../model.js";
import type { ChallengeRepository, EmailChallengeRepository } from "../../repository.js";
import { emailChallenges, webauthnChallenges } from "./schema.js";
import { clean, isUuid, write, type Db, type Tx } from "./shared.js";

export class DrizzleChallengeRepository implements ChallengeRepository {
  constructor(private readonly db: Db) {}

  create(c: WebAuthnChallenge): Promise<void> {
    return write("Challenge", () => this.db.insert(webauthnChallenges).values(c));
  }

  /** DELETE ... RETURNING is atomic => single use. */
  async consume(id: string, type: WebAuthnChallenge["type"]): Promise<WebAuthnChallenge | null> {
    const [row] = await this.db
      .delete(webauthnChallenges)
      .where(and(eq(webauthnChallenges.id, id), eq(webauthnChallenges.type, type)))
      .returning();
    return clean<WebAuthnChallenge>(row);
  }

  async purgeExpired(tx: Tx, now: Date): Promise<void> {
    await tx.delete(webauthnChallenges).where(lt(webauthnChallenges.expiresAt, now));
  }
}

export class DrizzleEmailChallengeRepository implements EmailChallengeRepository {
  constructor(private readonly db: Db) {}

  create(c: EmailChallenge): Promise<void> {
    return write("Email challenge", () => this.db.insert(emailChallenges).values(c));
  }

  async findActive(id: string, now: Date): Promise<EmailChallenge | null> {
    const [row] = await this.db.select().from(emailChallenges).where(and(eq(emailChallenges.id, id), gt(emailChallenges.expiresAt, now)));
    return clean<EmailChallenge>(row);
  }

  async findLatestActive(userId: string, purpose: EmailChallenge["purpose"], now: Date): Promise<EmailChallenge | null> {
    if (!isUuid(userId)) return null;
    const [row] = await this.db
      .select()
      .from(emailChallenges)
      .where(and(eq(emailChallenges.userId, userId), eq(emailChallenges.purpose, purpose), gt(emailChallenges.expiresAt, now)))
      .orderBy(desc(emailChallenges.sentAt))
      .limit(1);
    return clean<EmailChallenge>(row);
  }

  async recordFailedAttempt(id: string): Promise<number | null> {
    const [row] = await this.db
      .update(emailChallenges)
      .set({ attempts: sql`${emailChallenges.attempts} + 1` })
      .where(eq(emailChallenges.id, id))
      .returning({ attempts: emailChallenges.attempts });
    return row ? row.attempts : null;
  }

  async approve(id: string, at: Date): Promise<boolean> {
    const rows = await this.db.update(emailChallenges).set({ approvedAt: at }).where(eq(emailChallenges.id, id)).returning({ id: emailChallenges.id });
    return rows.length > 0;
  }

  async replaceCode(id: string, codeHash: string, sentAt: Date, expiresAt: Date): Promise<void> {
    await this.db
      .update(emailChallenges)
      .set({ codeHash, sentAt, expiresAt, attempts: 0, sends: sql`${emailChallenges.sends} + 1` })
      .where(eq(emailChallenges.id, id));
  }

  async consume(id: string): Promise<boolean> {
    return (await this.db.delete(emailChallenges).where(eq(emailChallenges.id, id)).returning({ id: emailChallenges.id })).length > 0;
  }

  async purgeExpired(tx: Tx, now: Date): Promise<void> {
    await tx.delete(emailChallenges).where(lt(emailChallenges.expiresAt, now));
  }
}
