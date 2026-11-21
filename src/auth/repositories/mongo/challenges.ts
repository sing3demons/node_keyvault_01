// Short-lived challenges: WebAuthn (passkey) challenges and emailed codes / links.

import type { Collection, Db } from "mongodb";
import type { EmailChallenge, WebAuthnChallenge } from "../../model.js";
import type { ChallengeRepository, EmailChallengeRepository } from "../../repository.js";
import { fromDoc, insertDoc, TTL, type Doc } from "./shared.js";

export class MongoChallengeRepository implements ChallengeRepository {
  private readonly col: Collection<Doc<WebAuthnChallenge>>;

  constructor(db: Db) {
    this.col = db.collection("webauthn_challenges");
  }

  create(c: WebAuthnChallenge): Promise<void> {
    return insertDoc(this.col, c, "Challenge");
  }

  async consume(id: string, type: WebAuthnChallenge["type"]): Promise<WebAuthnChallenge | null> {
    return fromDoc<WebAuthnChallenge>(await this.col.findOneAndDelete({ _id: id, type }));
  }

  async ensureIndexes(): Promise<void> {
    await this.col.createIndex({ expiresAt: 1 }, TTL);
  }
}

export class MongoEmailChallengeRepository implements EmailChallengeRepository {
  private readonly col: Collection<Doc<EmailChallenge>>;

  constructor(db: Db) {
    this.col = db.collection("email_challenges");
  }

  create(c: EmailChallenge): Promise<void> {
    return insertDoc(this.col, c, "Email challenge");
  }

  async findActive(id: string, now: Date): Promise<EmailChallenge | null> {
    return fromDoc<EmailChallenge>(await this.col.findOne({ _id: id, expiresAt: { $gt: now } }));
  }

  async recordFailedAttempt(id: string): Promise<number | null> {
    const doc = await this.col.findOneAndUpdate({ _id: id }, { $inc: { attempts: 1 } }, { returnDocument: "after" });
    return doc ? doc.attempts : null;
  }

  async approve(id: string, at: Date): Promise<boolean> {
    return (await this.col.updateOne({ _id: id }, { $set: { approvedAt: at } })).matchedCount > 0;
  }

  async replaceCode(id: string, codeHash: string, sentAt: Date, expiresAt: Date): Promise<void> {
    await this.col.updateOne({ _id: id }, { $set: { codeHash, sentAt, expiresAt, attempts: 0 }, $inc: { sends: 1 } });
  }

  async consume(id: string): Promise<boolean> {
    return (await this.col.deleteOne({ _id: id })).deletedCount > 0;
  }

  async ensureIndexes(): Promise<void> {
    await this.col.createIndex({ expiresAt: 1 }, TTL);
  }
}
