// Browsers a user signed in from (one row per user + device cookie).

import { and, desc, eq, sql } from "drizzle-orm";
import type { Device, DeviceSignIn } from "../../model.js";
import type { DeviceRepository } from "../../repository.js";
import { devices } from "./schema.js";
import { clean, isUuid, type Db } from "./shared.js";

export class DrizzleDeviceRepository implements DeviceRepository {
  constructor(private readonly db: Db) {}

  async recordSignIn(d: DeviceSignIn): Promise<string> {
    const latest = { name: d.name, userAgent: d.userAgent, ip: d.ip ?? null, lastSignInAt: d.at, lastSeenAt: d.at, lastMethod: d.method };
    const [row] = await this.db
      .insert(devices)
      .values({ id: d.id, userId: d.userId, keyHash: d.keyHash, createdAt: d.at, signIns: 1, ...latest })
      .onConflictDoUpdate({ target: [devices.userId, devices.keyHash], set: { ...latest, signIns: sql`${devices.signIns} + 1` } })
      .returning({ id: devices.id });
    return row!.id;
  }

  async listByUser(userId: string): Promise<Device[]> {
    if (!isUuid(userId)) return [];
    const rows = await this.db.select().from(devices).where(eq(devices.userId, userId)).orderBy(desc(devices.lastSeenAt));
    return rows.map((r) => clean<Device>(r)!);
  }

  async touch(id: string, at: Date): Promise<void> {
    if (!isUuid(id)) return;
    await this.db
      .update(devices)
      .set({ lastSeenAt: sql`GREATEST(${devices.lastSeenAt}, ${at})` })
      .where(eq(devices.id, id));
  }

  async delete(userId: string, id: string): Promise<boolean> {
    if (!isUuid(userId) || !isUuid(id)) return false;
    const rows = await this.db.delete(devices).where(and(eq(devices.id, id), eq(devices.userId, userId))).returning({ id: devices.id });
    return rows.length > 0;
  }
}
