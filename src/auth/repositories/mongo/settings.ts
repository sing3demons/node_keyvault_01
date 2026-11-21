// Server-wide settings as JSON values by key.

import type { Collection, Db } from "mongodb";
import type { SettingsRepository } from "../../repository.js";

export class MongoSettingsRepository implements SettingsRepository {
  private readonly col: Collection<{ _id: string; value: unknown; updatedAt: Date }>;

  constructor(db: Db) {
    this.col = db.collection("auth_settings");
  }

  async get<T>(key: string): Promise<T | null> {
    return ((await this.col.findOne({ _id: key }))?.value as T | undefined) ?? null;
  }

  async set(key: string, value: unknown): Promise<void> {
    await this.col.updateOne({ _id: key }, { $set: { value, updatedAt: new Date() } }, { upsert: true });
  }

  async delete(key: string): Promise<void> {
    await this.col.deleteOne({ _id: key });
  }
}
