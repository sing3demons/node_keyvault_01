// Server-wide settings as JSON values by key.

import { eq } from "drizzle-orm";
import type { SettingsRepository } from "../../repository.js";
import { authSettings } from "./schema.js";
import type { Db } from "./shared.js";

export class DrizzleSettingsRepository implements SettingsRepository {
  constructor(private readonly db: Db) {}

  async get<T>(key: string): Promise<T | null> {
    return ((await this.db.select().from(authSettings).where(eq(authSettings.key, key)))[0]?.value as T | undefined) ?? null;
  }

  async set(key: string, value: unknown): Promise<void> {
    const updatedAt = new Date();
    await this.db.insert(authSettings).values({ key, value, updatedAt }).onConflictDoUpdate({ target: authSettings.key, set: { value, updatedAt } });
  }

  async delete(key: string): Promise<void> {
    await this.db.delete(authSettings).where(eq(authSettings.key, key));
  }
}
