import { randomUUID } from "node:crypto";
import type { HashAlgorithm } from "../../shared/hashing.js";
import { MongoClient, ObjectId, type Collection, type Db, type Document } from "mongodb";
import type {
  Credential,
  AccessToken,
  Device,
  DeviceSignIn,
  EmailChallenge,
  AuthCode,
  AuthRequest,
  LocalizedProfile,
  OAuthClient,
  AccountUpdate,
  RefreshToken,
  Role,
  User,
  UserSummary,
  WebAuthnChallenge,
  WebAuthnCredential
} from "../model.js";
import { DuplicateKeyError, type AuthRepository } from "../repository.js";

// ---------------------------------------------------------------- document <-> domain mapping

/**
 * Users are stored as one document with profiles and credentials embedded:
 *   { _id, username, email?, profiles: [{ lang, firstName, lastName }], preferredLang?, createdAt,
 *     credentials: [{ id, type, key, value?, algorithm?, webauthn?, createdAt, lastUsedAt? }] }
 * `key` is storage-only and backs a unique multikey index:
 *   "<secretType>:<userId>" (one password / pin / ... per user) | "webauthn:<credId>" (credId globally unique).
 * (A unique index on credentials.webauthn.credId would collide on the null produced by password entries.)
 */
type CredentialElement = Credential & { key: string };
type UserDoc = Omit<User, "id" | "credentials"> & { _id: string; credentials: CredentialElement[] };

const credentialKey = (userId: string, c: Credential) =>
  c.type === "webauthn" ? `webauthn:${c.webauthn.credId}` : `${c.type}:${userId}`; // one secret of each type per user

const toElement = (userId: string, c: Credential): CredentialElement => {
  const el: Record<string, unknown> = { key: credentialKey(userId, c) };
  for (const [k, v] of Object.entries(c)) if (v !== undefined) el[k] = v;
  return el as unknown as CredentialElement;
};

const fromElement = ({ key: _key, ...rest }: CredentialElement): Credential => {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rest)) if (v !== null) out[k] = v;
  return out as unknown as Credential;
};

const userFromDoc = (doc: Document | null): User | null => {
  if (!doc) return null;
  const id = doc._id instanceof ObjectId ? doc._id.toHexString() : String(doc._id);
  return {
    id,
    username: doc.username,
    ...(typeof doc.email === "string" ? { email: doc.email } : {}),
    ...(doc.emailVerifiedAt instanceof Date ? { emailVerifiedAt: doc.emailVerifiedAt } : {}),
    profiles: ((doc.profiles ?? []) as LocalizedProfile[]).map(({ lang, firstName, lastName }) => ({ lang, firstName, lastName })),
    ...(typeof doc.preferredLang === "string" ? { preferredLang: doc.preferredLang } : {}),
    roles: Array.isArray(doc.roles) ? (doc.roles as Role[]) : [],
    createdAt: doc.createdAt,
    credentials: ((doc.credentials ?? []) as CredentialElement[]).map(fromElement)
  };
};

type Doc<T extends { id: string }> = Omit<T, "id"> & { _id: string };

const toDoc = <T extends { id: string }>({ id, ...rest }: T): Doc<T> => {
  const doc: Record<string, unknown> = { _id: id };
  for (const [k, v] of Object.entries(rest)) if (v !== undefined) doc[k] = v;
  return doc as Doc<T>;
};

const fromDoc = <T extends { id: string }>(doc: Document | null): T | null => {
  if (!doc) return null;
  const { _id, ...rest } = doc;
  const out: Record<string, unknown> = { id: _id };
  for (const [k, v] of Object.entries(rest)) if (v !== null) out[k] = v instanceof ObjectId ? v.toHexString() : v;
  if (_id instanceof ObjectId) out.id = _id.toHexString();
  return out as T;
};

/** MongoDB (native driver) implementation. Uses TTL indexes for expiry. */
export class MongoAuthRepository implements AuthRepository {
  private readonly db: Db;
  private readonly users$: Collection<UserDoc>;
  private readonly challenges$: Collection<Doc<WebAuthnChallenge>>;
  private readonly emailChallenges$: Collection<Doc<EmailChallenge>>;
  private readonly devices$: Collection<Doc<Device>>;
  private readonly clients$: Collection<Doc<OAuthClient>>;
  private readonly authRequests$: Collection<Doc<AuthRequest>>;
  private readonly authCodes$: Collection<Doc<AuthCode>>;
  private readonly access$: Collection<Doc<AccessToken>>;
  private readonly refresh$: Collection<Doc<RefreshToken>>;

  static async connect(url: string, dbName: string): Promise<MongoAuthRepository> {
    const client = new MongoClient(url);
    await client.connect();
    return new MongoAuthRepository(client, client.db(dbName));
  }

  constructor(
    private readonly client: MongoClient,
    db: Db
  ) {
    this.db = db;
    this.users$ = db.collection("users");
    this.challenges$ = db.collection("webauthn_challenges");
    this.emailChallenges$ = db.collection("email_challenges");
    this.devices$ = db.collection("devices");
    this.clients$ = db.collection("oauth_clients");
    this.authRequests$ = db.collection("auth_requests");
    this.authCodes$ = db.collection("auth_codes");
    this.access$ = db.collection("access_tokens");
    this.refresh$ = db.collection("refresh_tokens");
  }

  readonly users = {
    create: async (user: User) => {
      const doc: UserDoc = {
        _id: user.id,
        username: user.username,
        ...(user.email !== undefined ? { email: user.email } : {}),
        ...(user.emailVerifiedAt !== undefined ? { emailVerifiedAt: user.emailVerifiedAt } : {}),
        profiles: user.profiles,
        ...(user.preferredLang !== undefined ? { preferredLang: user.preferredLang } : {}),
        roles: user.roles,
        createdAt: user.createdAt,
        credentials: user.credentials.map((c) => toElement(user.id, c))
      };
      try {
        await this.users$.insertOne(doc);
      } catch (error) {
        throw this.duplicateError(error) ?? error;
      }
    },
    updateAccount: async (userId: string, update: AccountUpdate) => {
      const $set: Record<string, unknown> = {};
      const $unset: Record<string, ""> = {};
      if (update.email !== undefined) $set.email = update.email;
      if (update.emailVerifiedAt === null) $unset.emailVerifiedAt = "";
      else if (update.emailVerifiedAt !== undefined) $set.emailVerifiedAt = update.emailVerifiedAt;
      if (update.profiles !== undefined) $set.profiles = update.profiles;
      if (update.preferredLang === null) $unset.preferredLang = "";
      else if (update.preferredLang !== undefined) $set.preferredLang = update.preferredLang;
      if (Object.keys($set).length === 0 && Object.keys($unset).length === 0) return;
      try {
        await this.users$.updateOne({ _id: this.byId(userId) }, { $set, ...(Object.keys($unset).length ? { $unset } : {}) });
      } catch (error) {
        throw this.duplicateError(error) ?? error;
      }
    },
    findById: async (id: string) => userFromDoc(await this.users$.findOne({ _id: this.byId(id) })),
    list: async (): Promise<UserSummary[]> =>
      (
        await this.users$
          .find({}, { projection: { username: 1, email: 1, roles: 1, createdAt: 1 } })
          .sort({ createdAt: 1 })
          .toArray()
      ).map((d) => ({
        id: (d._id as unknown) instanceof ObjectId ? (d._id as unknown as ObjectId).toHexString() : String(d._id),
        username: d.username,
        ...(typeof d.email === "string" ? { email: d.email } : {}),
        roles: Array.isArray(d.roles) ? d.roles : [],
        createdAt: d.createdAt
      })),
    setRoles: async (userId: string, roles: Role[]) => {
      await this.users$.updateOne({ _id: this.byId(userId) }, { $set: { roles } });
    },
    findByUsername: async (username: string) => userFromDoc(await this.users$.findOne({ username })),
    findByEmail: async (email: string) => userFromDoc(await this.users$.findOne({ email })),
    markEmailVerified: async (userId: string, email: string, at: Date) =>
      (await this.users$.updateOne({ _id: this.byId(userId), email }, { $set: { emailVerifiedAt: at } })).matchedCount > 0,
    findByWebAuthnCredId: async (credId: string) => {
      const user = userFromDoc(await this.users$.findOne({ "credentials.key": `webauthn:${credId}` }));
      const credential = user?.credentials.find(
        (c): c is WebAuthnCredential => c.type === "webauthn" && c.webauthn.credId === credId
      );
      return user && credential ? { user, credential } : null;
    },
    addCredential: async (userId: string, credential: Credential) => {
      const element = toElement(userId, credential);
      try {
        // The unique index only spans documents; `$ne` also blocks a duplicate key inside this user's own array
        // (e.g. a second password, or the same passkey twice).
        const res = await this.users$.updateOne(
          { _id: this.byId(userId), "credentials.key": { $ne: element.key } },
          { $push: { credentials: element } }
        );
        if (res.matchedCount === 0 && (await this.users$.countDocuments({ _id: this.byId(userId) })) > 0) {
          throw new DuplicateKeyError("credential");
        }
      } catch (error) {
        throw this.duplicateError(error) ?? error;
      }
    },
    updateSecret: async (userId: string, credentialId: string, value: string, algorithm: HashAlgorithm) => {
      await this.users$.updateOne(
        { _id: this.byId(userId), "credentials.id": credentialId },
        { $set: { "credentials.$.value": value, "credentials.$.algorithm": algorithm } }
      );
    },
    recordWebAuthnUse: async (userId: string, credentialId: string, counter: number, usedAt: Date) => {
      await this.users$.updateOne(
        { _id: this.byId(userId), "credentials.id": credentialId },
        { $set: { "credentials.$.webauthn.counter": counter, "credentials.$.lastUsedAt": usedAt } }
      );
    },
    removeCredential: async (userId: string, credentialId: string) => {
      // single atomic update: only pull when at least 2 credentials exist
      const res = await this.users$.updateOne(
        { _id: this.byId(userId), "credentials.id": credentialId, "credentials.1": { $exists: true } },
        { $pull: { credentials: { id: credentialId } } }
      );
      if (res.modifiedCount > 0) return "removed" as const;
      const exists = await this.users$.countDocuments({ _id: this.byId(userId), "credentials.id": credentialId });
      return exists ? ("last_credential" as const) : ("not_found" as const);
    }
  };

  readonly challenges = {
    create: (c: WebAuthnChallenge) => this.insert(this.challenges$, c, "Challenge"),
    consume: async (id: string, type: WebAuthnChallenge["type"]) =>
      fromDoc<WebAuthnChallenge>(await this.challenges$.findOneAndDelete({ _id: id, type }))
  };

  readonly emailChallenges = {
    create: (c: EmailChallenge) => this.insert(this.emailChallenges$, c, "Email challenge"),
    findActive: async (id: string, now: Date) =>
      fromDoc<EmailChallenge>(await this.emailChallenges$.findOne({ _id: id, expiresAt: { $gt: now } })),
    recordFailedAttempt: async (id: string) => {
      const doc = await this.emailChallenges$.findOneAndUpdate(
        { _id: id },
        { $inc: { attempts: 1 } },
        { returnDocument: "after" }
      );
      return doc ? doc.attempts : null;
    },
    approve: async (id: string, at: Date) =>
      (await this.emailChallenges$.updateOne({ _id: id }, { $set: { approvedAt: at } })).matchedCount > 0,
    replaceCode: async (id: string, codeHash: string, sentAt: Date, expiresAt: Date) => {
      await this.emailChallenges$.updateOne(
        { _id: id },
        { $set: { codeHash, sentAt, expiresAt, attempts: 0 }, $inc: { sends: 1 } }
      );
    },
    consume: async (id: string) => (await this.emailChallenges$.deleteOne({ _id: id })).deletedCount > 0
  };

  readonly devices = {
    recordSignIn: async (d: DeviceSignIn) => {
      const doc = await this.devices$.findOneAndUpdate(
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
    },
    listByUser: async (userId: string) =>
      (await this.devices$.find({ userId }).sort({ lastSeenAt: -1 }).toArray()).map((d) => fromDoc<Device>(d)!),
    touch: async (id: string, at: Date) => {
      await this.devices$.updateOne({ _id: id }, { $max: { lastSeenAt: at } });
    },
    delete: async (userId: string, id: string) => (await this.devices$.deleteOne({ _id: id, userId })).deletedCount > 0
  };

  readonly clients = {
    create: (c: OAuthClient) => this.insert(this.clients$, c, "Client"),
    findById: async (id: string) => fromDoc<OAuthClient>(await this.clients$.findOne({ _id: id })),
    list: async () => (await this.clients$.find({}).sort({ createdAt: 1 }).toArray()).map((d) => fromDoc<OAuthClient>(d)!),
    update: async (c: OAuthClient) => {
      const { _id, createdAt: _createdAt, ...rest } = toDoc(c);
      const $unset: Record<string, ""> = {};
      for (const k of ["secretHash", "clientUri", "initiateLoginUri"] as const) if (c[k] === undefined) $unset[k] = "";
      const res = await this.clients$.updateOne(
        { _id },
        { $set: rest, ...(Object.keys($unset).length ? { $unset } : {}) } as never
      );
      return res.matchedCount > 0;
    },
    delete: async (id: string) => (await this.clients$.deleteOne({ _id: id })).deletedCount > 0
  };

  readonly authRequests = {
    create: (r: AuthRequest) => this.insert(this.authRequests$, r, "Authorization request"),
    findActive: async (id: string, now: Date) =>
      fromDoc<AuthRequest>(await this.authRequests$.findOne({ _id: id, expiresAt: { $gt: now } })),
    consumeActive: async (id: string, now: Date) =>
      fromDoc<AuthRequest>(await this.authRequests$.findOneAndDelete({ _id: id, expiresAt: { $gt: now } }))
  };

  readonly authCodes = {
    create: (c: AuthCode) => this.insert(this.authCodes$, c, "Authorization code"),
    redeem: async (id: string) =>
      fromDoc<AuthCode>(await this.authCodes$.findOneAndUpdate({ _id: id, used: false }, { $set: { used: true } })),
    find: async (id: string) => fromDoc<AuthCode>(await this.authCodes$.findOne({ _id: id }))
  };

  readonly tokens = {
    createPair: async (access: AccessToken, refresh: RefreshToken | null) => {
      await Promise.all([
        this.insert(this.access$, access, "Access token"),
        ...(refresh ? [this.insert(this.refresh$, refresh, "Refresh token")] : [])
      ]);
    },
    findActiveAccess: async (id: string, now: Date) =>
      fromDoc<AccessToken>(await this.access$.findOne({ _id: id, expiresAt: { $gt: now } })),
    findAccess: async (id: string) => fromDoc<AccessToken>(await this.access$.findOne({ _id: id })),
    findRefresh: async (id: string) => fromDoc<RefreshToken>(await this.refresh$.findOne({ _id: id })),
    rotateRefresh: async (id: string) =>
      fromDoc<RefreshToken>(await this.refresh$.findOneAndUpdate({ _id: id, revoked: false }, { $set: { revoked: true } })),
    revokeFamily: async (familyId: string) => {
      await Promise.all([
        this.refresh$.updateMany({ familyId }, { $set: { revoked: true } }),
        this.access$.deleteMany({ familyId })
      ]);
    },
    revokeDevice: async (userId: string, deviceId: string) => {
      await Promise.all([
        this.refresh$.updateMany({ userId, deviceId }, { $set: { revoked: true } }),
        this.access$.deleteMany({ userId, deviceId })
      ]);
    },
    revokeClient: async (clientId: string) => {
      await Promise.all([
        this.refresh$.updateMany({ clientId }, { $set: { revoked: true } }),
        this.access$.deleteMany({ clientId })
      ]);
    },
    activeDeviceIds: async (userId: string, now: Date) =>
      (
        await this.refresh$.distinct("deviceId", { userId, revoked: false, expiresAt: { $gt: now }, deviceId: { $type: "string" } })
      ).map(String)
  };

  async init(): Promise<void> {
    await this.migrateLegacyUsers();
    const ttl = { expireAfterSeconds: 0 };
    await Promise.all([
      this.users$.createIndex({ username: 1 }, { unique: true }),
      // partial: accounts created before email was collected have none
      this.users$.createIndex({ email: 1 }, { unique: true, partialFilterExpression: { email: { $type: "string" } } }),
      this.users$.createIndex(
        { "credentials.key": 1 },
        { unique: true, partialFilterExpression: { "credentials.key": { $exists: true } } }
      ),
      this.challenges$.createIndex({ expiresAt: 1 }, ttl),
      this.emailChallenges$.createIndex({ expiresAt: 1 }, ttl),
      this.devices$.createIndex({ userId: 1, keyHash: 1 }, { unique: true }),
      this.devices$.createIndex({ userId: 1, lastSeenAt: -1 }),
      this.authRequests$.createIndex({ expiresAt: 1 }, ttl),
      this.authCodes$.createIndex({ expiresAt: 1 }, ttl),
      this.access$.createIndex({ expiresAt: 1 }, ttl),
      this.access$.createIndex({ familyId: 1 }),
      this.access$.createIndex({ userId: 1, deviceId: 1 }),
      this.refresh$.createIndex({ expiresAt: 1 }, ttl),
      this.refresh$.createIndex({ familyId: 1 }),
      this.refresh$.createIndex({ userId: 1, deviceId: 1 })
    ]);
  }

  /**
   * One-time, idempotent upgrade from the earlier layout:
   *   users.passwordHash            -> credentials[{ type: "password", algorithm: "argon2id" }]
   *   webauthn_credentials (coll.)  -> credentials[{ type: "webauthn", webauthn: {...} }]
   */
  private async migrateLegacyUsers(): Promise<void> {
    const legacy = this.users$ as unknown as Collection<Document>;
    for await (const u of legacy.find({ passwordHash: { $exists: true } })) {
      const userId = u._id instanceof ObjectId ? u._id.toHexString() : String(u._id);
      const password: Credential = {
        id: randomUUID(),
        type: "password",
        value: u.passwordHash,
        algorithm: (u.passwordHash as string).startsWith("$argon2") ? "argon2id" : "bcrypt",
        createdAt: u.createdAt ?? new Date()
      };
      await legacy.updateOne(
        { _id: u._id, passwordHash: { $exists: true } },
        { $push: { credentials: toElement(userId, password) }, $unset: { passwordHash: "" } } as never
      );
    }

    const oldCreds = this.db.collection<Document>("webauthn_credentials");
    for await (const c of oldCreds.find({})) {
      const userId = c.userId instanceof ObjectId ? c.userId.toHexString() : String(c.userId);
      const passkey: Credential = {
        id: c._id instanceof ObjectId ? c._id.toHexString() : String(c._id),
        type: "webauthn",
        webauthn: {
          credId: c.credId,
          publicKeyPem: c.publicKeyPem,
          counter: c.counter ?? 0,
          transports: c.transports ?? undefined,
          name: c.name ?? "Passkey"
        },
        createdAt: c.createdAt ?? new Date(),
        lastUsedAt: c.lastUsedAt ?? undefined
      };
      await legacy.updateOne(
        { _id: this.byId(userId) as never, "credentials.key": { $ne: credentialKey(userId, passkey) } },
        { $push: { credentials: toElement(userId, passkey) } } as never
      );
      await oldCreds.deleteOne({ _id: c._id });
    }
    if ((await this.db.listCollections({ name: "webauthn_credentials" }).toArray()).length > 0) {
      if ((await oldCreds.countDocuments()) === 0) await oldCreds.drop();
    }
  }

  async close(): Promise<void> {
    await this.client.close();
  }

  // ---------------------------------------------------------------- query helpers

  /**
   * Ids are strings (UUID) now; documents written by the earlier Mongo-only version used ObjectId.
   * Match either form so existing users/passkeys keep working.
   */
  private byId(id: string): string {
    return (/^[0-9a-f]{24}$/i.test(id) ? { $in: [id, new ObjectId(id)] } : id) as unknown as string;
  }

  /** E11000 -> DuplicateKeyError naming the colliding field (from the violated index); otherwise null. */
  private duplicateError(error: unknown): DuplicateKeyError | null {
    const e = error as { code?: number; keyPattern?: Record<string, unknown> };
    if (e.code !== 11000) return null;
    const key = Object.keys(e.keyPattern ?? {})[0] ?? "";
    if (key === "username" || key === "email") return new DuplicateKeyError(key);
    if (key.startsWith("credentials")) return new DuplicateKeyError("credential");
    return new DuplicateKeyError("id");
  }

  private async insert<T extends { id: string }>(col: Collection<Doc<T>>, value: T, what: string): Promise<void> {
    try {
      await col.insertOne(toDoc(value) as never);
    } catch (error) {
      if (this.duplicateError(error)) throw new DuplicateKeyError("id", `${what} already exists`);
      throw error;
    }
  }
}
