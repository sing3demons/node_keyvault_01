// Users: `users` + `user_profiles` (one row per language) + `user_credentials` (one row per credential).

import { and, asc, count, eq, inArray, ne } from "drizzle-orm";
import type { HashAlgorithm } from "../../../shared/hashing.js";
import type {
  AccountUpdate,
  Credential,
  LocalizedProfile,
  Role,
  User,
  UserRef,
  UserSummary,
  WebAuthnCredential
} from "../../model.js";
import type { UserRepository } from "../../repository.js";
import { userCredentials, userProfiles, users } from "./schema.js";
import { isUuid, write, type Db } from "./shared.js";

type CredentialRow = typeof userCredentials.$inferSelect;
type CredentialInsert = typeof userCredentials.$inferInsert;

/** Domain credential -> flat row (columns of the other type stay NULL). */
function toRow(userId: string, c: Credential): CredentialInsert {
  const base = { id: c.id, userId, type: c.type, createdAt: c.createdAt, lastUsedAt: c.lastUsedAt };
  if (c.type !== "webauthn") return { ...base, value: c.value, algorithm: c.algorithm };
  const w = c.webauthn;
  return { ...base, credId: w.credId, publicKeyPem: w.publicKeyPem, counter: w.counter, transports: w.transports, name: w.name };
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

const profileRows = (userId: string, profiles: LocalizedProfile[]): (typeof userProfiles.$inferInsert)[] =>
  profiles.map((n, position) => ({ userId, ...n, position }));

export class DrizzleUserRepository implements UserRepository {
  constructor(private readonly db: Db) {}

  create(user: User): Promise<void> {
    return write("User", () =>
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
        if (user.profiles.length > 0) await tx.insert(userProfiles).values(profileRows(user.id, user.profiles));
        if (user.credentials.length > 0) await tx.insert(userCredentials).values(user.credentials.map((c) => toRow(user.id, c)));
      })
    );
  }

  updateAccount(userId: string, update: AccountUpdate): Promise<void> {
    return write("User", () =>
      this.db.transaction(async (tx) => {
        const set: Partial<typeof users.$inferInsert> = {};
        if (update.email !== undefined) set.email = update.email;
        if (update.emailVerifiedAt !== undefined) set.emailVerifiedAt = update.emailVerifiedAt; // null clears
        if (update.preferredLang !== undefined) set.preferredLang = update.preferredLang; // null clears
        if (Object.keys(set).length > 0) await tx.update(users).set(set).where(eq(users.id, userId));
        if (update.profiles !== undefined) {
          await tx.delete(userProfiles).where(eq(userProfiles.userId, userId));
          if (update.profiles.length > 0) await tx.insert(userProfiles).values(profileRows(userId, update.profiles));
        }
      })
    );
  }

  async findById(id: string): Promise<User | null> {
    if (!isUuid(id)) return null; // uuid column would reject other formats
    return this.load((await this.db.select().from(users).where(eq(users.id, id)))[0]);
  }

  async list(): Promise<UserSummary[]> {
    const rows = await this.db
      .select({ id: users.id, username: users.username, email: users.email, roles: users.roles, createdAt: users.createdAt })
      .from(users)
      .orderBy(asc(users.createdAt));
    return rows.map((r) => ({ id: r.id, username: r.username, ...(r.email !== null ? { email: r.email } : {}), roles: r.roles, createdAt: r.createdAt }));
  }

  async setRoles(userId: string, roles: Role[]): Promise<void> {
    if (!isUuid(userId)) return;
    await this.db.update(users).set({ roles }).where(eq(users.id, userId));
  }

  async findByUsername(username: string): Promise<User | null> {
    return this.load((await this.db.select().from(users).where(eq(users.username, username)))[0]);
  }

  async findRefByUsername(username: string): Promise<UserRef | null> {
    return (await this.db.select({ id: users.id, username: users.username }).from(users).where(eq(users.username, username)))[0] ?? null;
  }

  async findRefs(ids: string[]): Promise<UserRef[]> {
    const valid = [...new Set(ids)].filter(isUuid); // uuid column rejects other formats
    if (valid.length === 0) return [];
    return this.db.select({ id: users.id, username: users.username }).from(users).where(inArray(users.id, valid));
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.load((await this.db.select().from(users).where(eq(users.email, email)))[0]);
  }

  async markEmailVerified(userId: string, email: string, at: Date): Promise<boolean> {
    if (!isUuid(userId)) return false;
    const rows = await this.db
      .update(users)
      .set({ emailVerifiedAt: at })
      .where(and(eq(users.id, userId), eq(users.email, email)))
      .returning({ id: users.id });
    return rows.length > 0;
  }

  async findByWebAuthnCredId(credId: string): Promise<{ user: User; credential: WebAuthnCredential } | null> {
    const row = (await this.db.select().from(userCredentials).where(eq(userCredentials.credId, credId)))[0];
    if (!row) return null;
    const user = await this.findById(row.userId);
    const credential = user?.credentials.find((c): c is WebAuthnCredential => c.id === row.id && c.type === "webauthn");
    return user && credential ? { user, credential } : null;
  }

  addCredential(userId: string, credential: Credential): Promise<void> {
    return write("Credential", () => this.db.insert(userCredentials).values(toRow(userId, credential)));
  }

  async updateSecret(userId: string, credentialId: string, value: string, algorithm: HashAlgorithm): Promise<void> {
    await this.db
      .update(userCredentials)
      .set({ value, algorithm })
      .where(and(eq(userCredentials.id, credentialId), eq(userCredentials.userId, userId), ne(userCredentials.type, "webauthn")));
  }

  async recordWebAuthnUse(userId: string, credentialId: string, counter: number, usedAt: Date): Promise<void> {
    await this.db
      .update(userCredentials)
      .set({ counter, lastUsedAt: usedAt })
      .where(and(eq(userCredentials.id, credentialId), eq(userCredentials.userId, userId)));
  }

  async renameWebAuthn(userId: string, credentialId: string, name: string): Promise<boolean> {
    if (!isUuid(userId) || !isUuid(credentialId)) return false;
    const updated = await this.db
      .update(userCredentials)
      .set({ name })
      .where(and(eq(userCredentials.id, credentialId), eq(userCredentials.userId, userId), eq(userCredentials.type, "webauthn")))
      .returning({ id: userCredentials.id });
    return updated.length > 0;
  }

  async removeCredential(userId: string, credentialId: string): Promise<"removed" | "not_found" | "last_credential"> {
    if (!isUuid(userId) || !isUuid(credentialId)) return "not_found";
    return this.db.transaction(async (tx) => {
      // lock the user row so concurrent removals cannot both pass the "not the last one" check
      const owner = await tx.select({ id: users.id }).from(users).where(eq(users.id, userId)).for("update");
      if (owner.length === 0) return "not_found" as const;
      const [{ total }] = await tx.select({ total: count() }).from(userCredentials).where(eq(userCredentials.userId, userId));
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

  private async load(row: typeof users.$inferSelect | undefined): Promise<User | null> {
    if (!row) return null;
    const [profiles, creds] = await Promise.all([
      this.db.select().from(userProfiles).where(eq(userProfiles.userId, row.id)).orderBy(asc(userProfiles.position)),
      this.db.select().from(userCredentials).where(eq(userCredentials.userId, row.id)).orderBy(asc(userCredentials.createdAt))
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
}
