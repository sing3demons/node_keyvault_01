// PostgreSQL implementation of AuthRepository via Drizzle ORM (node-postgres driver): one repository per
// table group. Migrations in ./drizzle run on init(); Postgres has no TTL indexes, so expired rows are
// swept on a timer.

import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";
import type { AuthRepository } from "../../repository.js";
import { DrizzleChallengeRepository, DrizzleEmailChallengeRepository } from "./challenges.js";
import { DrizzleClientRepository } from "./clients.js";
import { DrizzleDeviceRepository } from "./devices.js";
import { DrizzleAuthCodeRepository, DrizzleAuthRequestRepository, DrizzleTokenRepository } from "./oauth.js";
import * as schema from "./schema.js";
import { DrizzleSettingsRepository } from "./settings.js";
import type { Db } from "./shared.js";
import { DrizzleUserRepository } from "./users.js";

export class DrizzleAuthRepository implements AuthRepository {
  /** Expired rows are swept on this interval once `init()` ran. */
  private static readonly PURGE_INTERVAL_MS = 10 * 60_000;
  private purgeTimer?: NodeJS.Timeout;
  private readonly db: Db;

  readonly users: DrizzleUserRepository;
  readonly challenges: DrizzleChallengeRepository;
  readonly emailChallenges: DrizzleEmailChallengeRepository;
  readonly devices: DrizzleDeviceRepository;
  readonly clients: DrizzleClientRepository;
  readonly settings: DrizzleSettingsRepository;
  readonly authRequests: DrizzleAuthRequestRepository;
  readonly authCodes: DrizzleAuthCodeRepository;
  readonly tokens: DrizzleTokenRepository;

  static connect(connectionString: string, migrationsFolder: string): DrizzleAuthRepository {
    return new DrizzleAuthRepository(new Pool({ connectionString }), migrationsFolder);
  }

  constructor(
    private readonly pool: Pool,
    private readonly migrationsFolder: string
  ) {
    this.db = drizzle(pool, { schema });
    this.users = new DrizzleUserRepository(this.db);
    this.challenges = new DrizzleChallengeRepository(this.db);
    this.emailChallenges = new DrizzleEmailChallengeRepository(this.db);
    this.devices = new DrizzleDeviceRepository(this.db);
    this.clients = new DrizzleClientRepository(this.db);
    this.settings = new DrizzleSettingsRepository(this.db);
    this.authRequests = new DrizzleAuthRequestRepository(this.db);
    this.authCodes = new DrizzleAuthCodeRepository(this.db);
    this.tokens = new DrizzleTokenRepository(this.db);
  }

  async init(): Promise<void> {
    await migrate(this.db, { migrationsFolder: this.migrationsFolder });
    this.purgeTimer ??= setInterval(
      () => this.purgeExpired(new Date()).catch((e) => console.error("purgeExpired failed", e)),
      DrizzleAuthRepository.PURGE_INTERVAL_MS
    ).unref();
  }

  /** Deletes expired challenges, requests, codes and tokens (run by the timer started in `init()`). */
  async purgeExpired(now: Date): Promise<void> {
    await this.db.transaction(async (tx) => {
      await this.challenges.purgeExpired(tx, now);
      await this.emailChallenges.purgeExpired(tx, now);
      await this.authRequests.purgeExpired(tx, now);
      await this.authCodes.purgeExpired(tx, now);
      await this.tokens.purgeExpired(tx, now);
    });
  }

  async close(): Promise<void> {
    clearInterval(this.purgeTimer);
    this.purgeTimer = undefined;
    await this.pool.end();
  }
}
