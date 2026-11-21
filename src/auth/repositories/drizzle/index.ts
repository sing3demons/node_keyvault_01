import { and, asc, eq, gt, lt } from "drizzle-orm";
import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";
import {
  DuplicateKeyError,
  type AccessToken,
  type AuthCode,
  type AuthRepository,
  type AuthRequest,
  type RefreshToken,
  type User,
  type WebAuthnChallenge,
  type WebAuthnCredential
} from "../../repository.js";
import * as schema from "./schema.js";

const { users, webauthnCredentials, webauthnChallenges, authRequests, authCodes, accessTokens, refreshTokens } = schema;

type Db = NodePgDatabase<typeof schema>;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** SQL NULL -> undefined so rows match the domain types. */
const clean = <T>(row: Record<string, unknown> | undefined): T | null => {
  if (!row) return null;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) if (v !== null) out[k] = v;
  return out as T;
};

/** Postgres unique_violation, possibly wrapped by DrizzleQueryError. */
const isDuplicate = (error: unknown): boolean => {
  const e = error as { code?: string; cause?: { code?: string } };
  return e.code === "23505" || e.cause?.code === "23505";
};

async function insert(what: string, run: () => Promise<unknown>): Promise<void> {
  try {
    await run();
  } catch (error) {
    if (isDuplicate(error)) throw new DuplicateKeyError(`${what} already exists`);
    throw error;
  }
}

/** PostgreSQL implementation via Drizzle ORM (node-postgres driver). */
export class DrizzleAuthRepository implements AuthRepository {
  private readonly db: Db;

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
    create: (user: User) => insert("Username", () => this.db.insert(users).values(user)),
    findById: async (id: string) => clean<User>((await this.db.select().from(users).where(eq(users.id, id)))[0]),
    findByUsername: async (username: string) =>
      clean<User>((await this.db.select().from(users).where(eq(users.username, username)))[0]),
    updatePasswordHash: async (id: string, passwordHash: string) => {
      await this.db.update(users).set({ passwordHash }).where(eq(users.id, id));
    }
  };

  readonly credentials = {
    create: (cred: WebAuthnCredential) => insert("Passkey", () => this.db.insert(webauthnCredentials).values(cred)),
    findByCredId: async (credId: string) =>
      clean<WebAuthnCredential>(
        (await this.db.select().from(webauthnCredentials).where(eq(webauthnCredentials.credId, credId)))[0]
      ),
    listByUser: async (userId: string) =>
      (
        await this.db
          .select()
          .from(webauthnCredentials)
          .where(eq(webauthnCredentials.userId, userId))
          .orderBy(asc(webauthnCredentials.createdAt))
      ).map((r) => clean<WebAuthnCredential>(r)!),
    recordUse: async (id: string, counter: number, usedAt: Date) => {
      await this.db.update(webauthnCredentials).set({ counter, lastUsedAt: usedAt }).where(eq(webauthnCredentials.id, id));
    },
    delete: async (userId: string, id: string) => {
      if (!UUID_RE.test(id)) return false; // uuid column would reject other formats
      const rows = await this.db
        .delete(webauthnCredentials)
        .where(and(eq(webauthnCredentials.id, id), eq(webauthnCredentials.userId, userId)))
        .returning({ id: webauthnCredentials.id });
      return rows.length > 0;
    }
  };

  readonly challenges = {
    create: (c: WebAuthnChallenge) => insert("Challenge", () => this.db.insert(webauthnChallenges).values(c)),
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

  readonly authRequests = {
    create: (r: AuthRequest) => insert("Authorization request", () => this.db.insert(authRequests).values(r)),
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
    create: (c: AuthCode) => insert("Authorization code", () => this.db.insert(authCodes).values(c)),
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
      insert("Token", () =>
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
    }
  };

  async init(): Promise<void> {
    await migrate(this.db, { migrationsFolder: this.migrationsFolder });
  }

  /** Postgres has no TTL — called periodically by the server. */
  async purgeExpired(now: Date): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.delete(webauthnChallenges).where(lt(webauthnChallenges.expiresAt, now));
      await tx.delete(authRequests).where(lt(authRequests.expiresAt, now));
      await tx.delete(authCodes).where(lt(authCodes.expiresAt, now));
      await tx.delete(accessTokens).where(lt(accessTokens.expiresAt, now));
      await tx.delete(refreshTokens).where(lt(refreshTokens.expiresAt, now));
    });
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
