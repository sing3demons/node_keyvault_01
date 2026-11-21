import { and, asc, count, desc, eq, gt, isNotNull, lt, ne, sql } from "drizzle-orm";
import type { HashAlgorithm } from "../../../shared/hashing.js";
import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";
import type {
  Credential,
  AccessToken,
  Device,
  DeviceSignIn,
  EmailChallenge,
  AuthCode,
  AuthRequest,
  LocalizedProfile,
  AccountUpdate,
  RefreshToken,
  Role,
  User,
  UserSummary,
  WebAuthnChallenge,
  WebAuthnCredential
} from "../../model.js";
import { DuplicateKeyError, type AuthRepository } from "../../repository.js";
import * as schema from "./schema.js";

const {
  users,
  userProfiles,
  userCredentials,
  webauthnChallenges,
  emailChallenges,
  devices,
  authRequests,
  authCodes,
  accessTokens,
  refreshTokens
} = schema;

type Db = NodePgDatabase<typeof schema>;
// ---------------------------------------------------------------- row <-> domain mapping

type CredentialRow = typeof userCredentials.$inferSelect;
type CredentialInsert = typeof userCredentials.$inferInsert;

/** Domain credential -> flat row (columns of the other type stay NULL). */
function toRow(userId: string, c: Credential): CredentialInsert {
  const base = { id: c.id, userId, type: c.type, createdAt: c.createdAt, lastUsedAt: c.lastUsedAt };
  if (c.type !== "webauthn") return { ...base, value: c.value, algorithm: c.algorithm };
  const w = c.webauthn;
  return {
    ...base,
    credId: w.credId,
    publicKeyPem: w.publicKeyPem,
    counter: w.counter,
    transports: w.transports,
    name: w.name
  };
}

/** Flat row -> domain credential. */
function fromRow(r: CredentialRow): Credential {
  const base = { id: r.id, createdAt: r.createdAt, ...(r.lastUsedAt ? { lastUsedAt: r.lastUsedAt } : {}) };
  if (r.type !== "webauthn") {
    return { ...base, type: r.type, value: r.value!, algorithm: r.algorithm! };
  }
  return {
    ...base,
    type: "webauthn",
    webauthn: {
      credId: r.credId!,
      publicKeyPem: r.publicKeyPem!,
      counter: r.counter!,
      ...(r.transports ? { transports: r.transports } : {}),
      name: r.name!
    }
  };
}

/** SQL NULL -> undefined so rows match the domain types. */
const clean = <T>(row: Record<string, unknown> | undefined): T | null => {
  if (!row) return null;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) if (v !== null) out[k] = v;
  return out as T;
};

/** PostgreSQL implementation via Drizzle ORM (node-postgres driver). */
export class DrizzleAuthRepository implements AuthRepository {
  private static readonly UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  private readonly db: Db;

  /** Postgres has no TTL indexes, so expired rows are swept on this interval once `init()` ran. */
  private static readonly PURGE_INTERVAL_MS = 10 * 60_000;
  private purgeTimer?: NodeJS.Timeout;

  static connect(connectionString: string, migrationsFolder: string): DrizzleAuthRepository {
    return new DrizzleAuthRepository(new Pool({ connectionString }), migrationsFolder);
  }

  constructor(
    private readonly pool: Pool,
    private readonly migrationsFolder: string
  ) {
    this.db = drizzle(pool, { schema });
  }

  readonly users = {
    create: (user: User) =>
      this.insert("User", () =>
        this.db.transaction(async (tx) => {
          await tx.insert(users).values({
            id: user.id,
            username: user.username,
            email: user.email,
            emailVerifiedAt: user.emailVerifiedAt,
            preferredLang: user.preferredLang,
            roles: user.roles,
            createdAt: user.createdAt
          });
          if (user.profiles.length > 0) {
            await tx.insert(userProfiles).values(this.profileRows(user.id, user.profiles));
          }
          if (user.credentials.length > 0) {
            await tx.insert(userCredentials).values(user.credentials.map((c) => toRow(user.id, c)));
          }
        })
      ),
    updateAccount: (userId: string, update: AccountUpdate) =>
      this.insert("User", () =>
        this.db.transaction(async (tx) => {
          const set: Partial<typeof users.$inferInsert> = {};
          if (update.email !== undefined) set.email = update.email;
          if (update.emailVerifiedAt !== undefined) set.emailVerifiedAt = update.emailVerifiedAt; // null clears
          if (update.preferredLang !== undefined) set.preferredLang = update.preferredLang; // null clears
          if (Object.keys(set).length > 0) await tx.update(users).set(set).where(eq(users.id, userId));
          if (update.profiles !== undefined) {
            await tx.delete(userProfiles).where(eq(userProfiles.userId, userId));
            if (update.profiles.length > 0) await tx.insert(userProfiles).values(this.profileRows(userId, update.profiles));
          }
        })
      ),
    findById: async (id: string) => {
      if (!this.isUuid(id)) return null; // uuid column would reject other formats
      return this.loadUser((await this.db.select().from(users).where(eq(users.id, id)))[0]);
    },
    list: async (): Promise<UserSummary[]> =>
      (
        await this.db
          .select({ id: users.id, username: users.username, email: users.email, roles: users.roles, createdAt: users.createdAt })
          .from(users)
          .orderBy(asc(users.createdAt))
      ).map((r) => ({ id: r.id, username: r.username, ...(r.email !== null ? { email: r.email } : {}), roles: r.roles, createdAt: r.createdAt })),
    setRoles: async (userId: string, roles: Role[]) => {
      if (!this.isUuid(userId)) return;
      await this.db.update(users).set({ roles }).where(eq(users.id, userId));
    },
    findByUsername: async (username: string) =>
      this.loadUser((await this.db.select().from(users).where(eq(users.username, username)))[0]),
    findByEmail: async (email: string) => this.loadUser((await this.db.select().from(users).where(eq(users.email, email)))[0]),
    markEmailVerified: async (userId: string, email: string, at: Date) => {
      if (!this.isUuid(userId)) return false;
      const rows = await this.db
        .update(users)
        .set({ emailVerifiedAt: at })
        .where(and(eq(users.id, userId), eq(users.email, email)))
        .returning({ id: users.id });
      return rows.length > 0;
    },
    findByWebAuthnCredId: async (credId: string) => {
      const row = (await this.db.select().from(userCredentials).where(eq(userCredentials.credId, credId)))[0];
      if (!row) return null;
      const user = await this.users.findById(row.userId);
      const credential = user?.credentials.find((c): c is WebAuthnCredential => c.id === row.id && c.type === "webauthn");
      return user && credential ? { user, credential } : null;
    },
    addCredential: (userId: string, credential: Credential) =>
      this.insert("Credential", () => this.db.insert(userCredentials).values(toRow(userId, credential))),
    updateSecret: async (userId: string, credentialId: string, value: string, algorithm: HashAlgorithm) => {
      await this.db
        .update(userCredentials)
        .set({ value, algorithm })
        .where(
          and(eq(userCredentials.id, credentialId), eq(userCredentials.userId, userId), ne(userCredentials.type, "webauthn"))
        );
    },
    recordWebAuthnUse: async (userId: string, credentialId: string, counter: number, usedAt: Date) => {
      await this.db
        .update(userCredentials)
        .set({ counter, lastUsedAt: usedAt })
        .where(and(eq(userCredentials.id, credentialId), eq(userCredentials.userId, userId)));
    },
    removeCredential: async (userId: string, credentialId: string) => {
      if (!this.isUuid(userId) || !this.isUuid(credentialId)) return "not_found" as const;
      return this.db.transaction(async (tx) => {
        // lock the user row so concurrent removals cannot both pass the "not the last one" check
        const owner = await tx.select({ id: users.id }).from(users).where(eq(users.id, userId)).for("update");
        if (owner.length === 0) return "not_found" as const;
        const [{ total }] = await tx
          .select({ total: count() })
          .from(userCredentials)
          .where(eq(userCredentials.userId, userId));
        const target = await tx
          .select({ id: userCredentials.id })
          .from(userCredentials)
          .where(and(eq(userCredentials.id, credentialId), eq(userCredentials.userId, userId)));
        if (target.length === 0) return "not_found" as const;
        if (total <= 1) return "last_credential" as const;
        await tx.delete(userCredentials).where(eq(userCredentials.id, credentialId));
        return "removed" as const;
      });
    }
  };

  private async loadUser(row: typeof users.$inferSelect | undefined): Promise<User | null> {
    if (!row) return null;
    const [profiles, creds] = await Promise.all([
      this.db.select().from(userProfiles).where(eq(userProfiles.userId, row.id)).orderBy(asc(userProfiles.position)),
      this.db
        .select()
        .from(userCredentials)
        .where(eq(userCredentials.userId, row.id))
        .orderBy(asc(userCredentials.createdAt))
    ]);
    return {
      id: row.id,
      username: row.username,
      ...(row.email !== null ? { email: row.email } : {}),
      ...(row.emailVerifiedAt !== null ? { emailVerifiedAt: row.emailVerifiedAt } : {}),
      profiles: profiles.map(({ lang, firstName, lastName }) => ({ lang, firstName, lastName })),
      ...(row.preferredLang !== null ? { preferredLang: row.preferredLang } : {}),
      roles: row.roles,
      createdAt: row.createdAt,
      credentials: creds.map(fromRow)
    };
  }

  private profileRows(userId: string, profiles: LocalizedProfile[]): (typeof userProfiles.$inferInsert)[] {
    return profiles.map((n, position) => ({ userId, ...n, position }));
  }

  readonly challenges = {
    create: (c: WebAuthnChallenge) => this.insert("Challenge", () => this.db.insert(webauthnChallenges).values(c)),
    // DELETE ... RETURNING is atomic => single use
    consume: async (id: string, type: WebAuthnChallenge["type"]) =>
      clean<WebAuthnChallenge>(
        (
          await this.db
            .delete(webauthnChallenges)
            .where(and(eq(webauthnChallenges.id, id), eq(webauthnChallenges.type, type)))
            .returning()
        )[0]
      )
  };

  readonly emailChallenges = {
    create: (c: EmailChallenge) => this.insert("Email challenge", () => this.db.insert(emailChallenges).values(c)),
    findActive: async (id: string, now: Date) =>
      clean<EmailChallenge>(
        (await this.db.select().from(emailChallenges).where(and(eq(emailChallenges.id, id), gt(emailChallenges.expiresAt, now))))[0]
      ),
    recordFailedAttempt: async (id: string) => {
      const [row] = await this.db
        .update(emailChallenges)
        .set({ attempts: sql`${emailChallenges.attempts} + 1` })
        .where(eq(emailChallenges.id, id))
        .returning({ attempts: emailChallenges.attempts });
      return row ? row.attempts : null;
    },
    approve: async (id: string, at: Date) =>
      (
        await this.db
          .update(emailChallenges)
          .set({ approvedAt: at })
          .where(eq(emailChallenges.id, id))
          .returning({ id: emailChallenges.id })
      ).length > 0,
    replaceCode: async (id: string, codeHash: string, sentAt: Date, expiresAt: Date) => {
      await this.db
        .update(emailChallenges)
        .set({ codeHash, sentAt, expiresAt, attempts: 0, sends: sql`${emailChallenges.sends} + 1` })
        .where(eq(emailChallenges.id, id));
    },
    consume: async (id: string) =>
      (await this.db.delete(emailChallenges).where(eq(emailChallenges.id, id)).returning({ id: emailChallenges.id })).length > 0
  };

  readonly devices = {
    recordSignIn: async (d: DeviceSignIn) => {
      const latest = { name: d.name, userAgent: d.userAgent, ip: d.ip ?? null, lastSignInAt: d.at, lastSeenAt: d.at, lastMethod: d.method };
      const [row] = await this.db
        .insert(devices)
        .values({ id: d.id, userId: d.userId, keyHash: d.keyHash, createdAt: d.at, signIns: 1, ...latest })
        .onConflictDoUpdate({
          target: [devices.userId, devices.keyHash],
          set: { ...latest, signIns: sql`${devices.signIns} + 1` }
        })
        .returning({ id: devices.id });
      return row!.id;
    },
    listByUser: async (userId: string): Promise<Device[]> => {
      if (!this.isUuid(userId)) return [];
      const rows = await this.db.select().from(devices).where(eq(devices.userId, userId)).orderBy(desc(devices.lastSeenAt));
      return rows.map((r) => clean<Device>(r)!);
    },
    touch: async (id: string, at: Date) => {
      if (!this.isUuid(id)) return;
      await this.db
        .update(devices)
        .set({ lastSeenAt: sql`GREATEST(${devices.lastSeenAt}, ${at})` })
        .where(eq(devices.id, id));
    },
    delete: async (userId: string, id: string) => {
      if (!this.isUuid(userId) || !this.isUuid(id)) return false;
      const rows = await this.db
        .delete(devices)
        .where(and(eq(devices.id, id), eq(devices.userId, userId)))
        .returning({ id: devices.id });
      return rows.length > 0;
    }
  };

  readonly authRequests = {
    create: (r: AuthRequest) => this.insert("Authorization request", () => this.db.insert(authRequests).values(r)),
    findActive: async (id: string, now: Date) =>
      clean<AuthRequest>(
        (await this.db.select().from(authRequests).where(and(eq(authRequests.id, id), gt(authRequests.expiresAt, now))))[0]
      ),
    consumeActive: async (id: string, now: Date) =>
      clean<AuthRequest>(
        (
          await this.db
            .delete(authRequests)
            .where(and(eq(authRequests.id, id), gt(authRequests.expiresAt, now)))
            .returning()
        )[0]
      )
  };

  readonly authCodes = {
    create: (c: AuthCode) => this.insert("Authorization code", () => this.db.insert(authCodes).values(c)),
    // UPDATE ... WHERE used = false RETURNING => only one concurrent redeemer wins
    redeem: async (id: string) =>
      clean<AuthCode>(
        (
          await this.db
            .update(authCodes)
            .set({ used: true })
            .where(and(eq(authCodes.id, id), eq(authCodes.used, false)))
            .returning()
        )[0]
      ),
    find: async (id: string) => clean<AuthCode>((await this.db.select().from(authCodes).where(eq(authCodes.id, id)))[0])
  };

  readonly tokens = {
    createPair: (access: AccessToken, refresh: RefreshToken) =>
      this.insert("Token", () =>
        this.db.transaction(async (tx) => {
          await tx.insert(accessTokens).values(access);
          await tx.insert(refreshTokens).values(refresh);
        })
      ),
    findActiveAccess: async (id: string, now: Date) =>
      clean<AccessToken>(
        (await this.db.select().from(accessTokens).where(and(eq(accessTokens.id, id), gt(accessTokens.expiresAt, now))))[0]
      ),
    findAccess: async (id: string) =>
      clean<AccessToken>((await this.db.select().from(accessTokens).where(eq(accessTokens.id, id)))[0]),
    findRefresh: async (id: string) =>
      clean<RefreshToken>((await this.db.select().from(refreshTokens).where(eq(refreshTokens.id, id)))[0]),
    rotateRefresh: async (id: string) =>
      clean<RefreshToken>(
        (
          await this.db
            .update(refreshTokens)
            .set({ revoked: true })
            .where(and(eq(refreshTokens.id, id), eq(refreshTokens.revoked, false)))
            .returning()
        )[0]
      ),
    revokeFamily: async (familyId: string) => {
      await this.db.transaction(async (tx) => {
        await tx.update(refreshTokens).set({ revoked: true }).where(eq(refreshTokens.familyId, familyId));
        await tx.delete(accessTokens).where(eq(accessTokens.familyId, familyId));
      });
    },
    revokeDevice: async (userId: string, deviceId: string) => {
      if (!this.isUuid(userId) || !this.isUuid(deviceId)) return;
      await this.db.transaction(async (tx) => {
        await tx
          .update(refreshTokens)
          .set({ revoked: true })
          .where(and(eq(refreshTokens.userId, userId), eq(refreshTokens.deviceId, deviceId)));
        await tx.delete(accessTokens).where(and(eq(accessTokens.userId, userId), eq(accessTokens.deviceId, deviceId)));
      });
    },
    activeDeviceIds: async (userId: string, now: Date) => {
      if (!this.isUuid(userId)) return [];
      const rows = await this.db
        .selectDistinct({ deviceId: refreshTokens.deviceId })
        .from(refreshTokens)
        .where(
          and(
            eq(refreshTokens.userId, userId),
            eq(refreshTokens.revoked, false),
            gt(refreshTokens.expiresAt, now),
            isNotNull(refreshTokens.deviceId)
          )
        );
      return rows.flatMap((r) => (r.deviceId ? [r.deviceId] : []));
    }
  };

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
      await tx.delete(webauthnChallenges).where(lt(webauthnChallenges.expiresAt, now));
      await tx.delete(emailChallenges).where(lt(emailChallenges.expiresAt, now));
      await tx.delete(authRequests).where(lt(authRequests.expiresAt, now));
      await tx.delete(authCodes).where(lt(authCodes.expiresAt, now));
      await tx.delete(accessTokens).where(lt(accessTokens.expiresAt, now));
      await tx.delete(refreshTokens).where(lt(refreshTokens.expiresAt, now));
    });
  }

  async close(): Promise<void> {
    clearInterval(this.purgeTimer);
    this.purgeTimer = undefined;
    await this.pool.end();
  }

  // ---------------------------------------------------------------- query helpers

  /** uuid columns reject other formats, so callers check before querying. */
  private isUuid(id: string): boolean {
    return DrizzleAuthRepository.UUID_RE.test(id);
  }

  /** Runs an insert, mapping Postgres unique_violation (possibly wrapped by DrizzleQueryError) to DuplicateKeyError. */
  /**
   * Runs a write, mapping Postgres unique_violation (possibly wrapped by DrizzleQueryError) to DuplicateKeyError,
   * naming the field from the violated constraint.
   */
  private async insert(what: string, run: () => Promise<unknown>): Promise<void> {
    try {
      await run();
    } catch (error) {
      const e = error as { code?: string; constraint?: string; cause?: { code?: string; constraint?: string } };
      const pg = e.cause?.code ? e.cause : e;
      if (pg.code !== "23505") throw error;
      const constraint = pg.constraint ?? "";
      if (constraint.includes("email")) throw new DuplicateKeyError("email");
      if (constraint.includes("username")) throw new DuplicateKeyError("username");
      if (constraint.startsWith("user_credentials")) throw new DuplicateKeyError("credential");
      throw new DuplicateKeyError("id", `${what} already exists`);
    }
  }
}
