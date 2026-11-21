// Registered OAuth clients.

import type { Collection, Db } from "mongodb";
import type { OAuthClient } from "../../model.js";
import type { ClientRepository } from "../../repository.js";
import { fromDoc, insertDoc, toDoc, type Doc } from "./shared.js";

/** Optional fields: unset in the document when the client no longer has them. */
const OPTIONAL = ["secretHash", "clientUri", "initiateLoginUri", "mailFrom"] as const;

export class MongoClientRepository implements ClientRepository {
  private readonly col: Collection<Doc<OAuthClient>>;

  constructor(db: Db) {
    this.col = db.collection("oauth_clients");
  }

  create(c: OAuthClient): Promise<void> {
    return insertDoc(this.col, c, "Client");
  }

  async findById(id: string): Promise<OAuthClient | null> {
    return fromDoc<OAuthClient>(await this.col.findOne({ _id: id }));
  }

  async list(): Promise<OAuthClient[]> {
    return (await this.col.find({}).sort({ createdAt: 1 }).toArray()).map((d) => fromDoc<OAuthClient>(d)!);
  }

  async update(c: OAuthClient): Promise<boolean> {
    const { _id, createdAt: _createdAt, ...rest } = toDoc(c);
    const $unset: Record<string, ""> = {};
    for (const k of OPTIONAL) if (c[k] === undefined) $unset[k] = "";
    const res = await this.col.updateOne({ _id }, { $set: rest, ...(Object.keys($unset).length ? { $unset } : {}) } as never);
    return res.matchedCount > 0;
  }

  async delete(id: string): Promise<boolean> {
    return (await this.col.deleteOne({ _id: id })).deletedCount > 0;
  }
}
