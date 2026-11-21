// Browsers a user signed in from (one document per user + device cookie).

import type { Collection, Db } from "mongodb";
import type { Device, DeviceSignIn } from "../../model.js";
import type { DeviceRepository } from "../../repository.js";
import { fromDoc, type Doc } from "./shared.js";

export class MongoDeviceRepository implements DeviceRepository {
  private readonly col: Collection<Doc<Device>>;

  constructor(db: Db) {
    this.col = db.collection("devices");
  }

  async recordSignIn(d: DeviceSignIn): Promise<string> {
    const doc = await this.col.findOneAndUpdate(
      { userId: d.userId, keyHash: d.keyHash },
      {
        $set: {
          name: d.name,
          userAgent: d.userAgent,
          ...(d.ip !== undefined ? { ip: d.ip } : {}),
          lastSignInAt: d.at,
          lastSeenAt: d.at,
          lastMethod: d.method
        },
        $setOnInsert: { _id: d.id, createdAt: d.at },
        $inc: { signIns: 1 }
      },
      { upsert: true, returnDocument: "after" }
    );
    return doc ? String(doc._id) : d.id;
  }

  async listByUser(userId: string): Promise<Device[]> {
    return (await this.col.find({ userId }).sort({ lastSeenAt: -1 }).toArray()).map((d) => fromDoc<Device>(d)!);
  }

  async touch(id: string, at: Date): Promise<void> {
    await this.col.updateOne({ _id: id }, { $max: { lastSeenAt: at } });
  }

  async delete(userId: string, id: string): Promise<boolean> {
    return (await this.col.deleteOne({ _id: id, userId })).deletedCount > 0;
  }

  async ensureIndexes(): Promise<void> {
    await Promise.all([
      this.col.createIndex({ userId: 1, keyHash: 1 }, { unique: true }),
      this.col.createIndex({ userId: 1, lastSeenAt: -1 })
    ]);
  }
}
