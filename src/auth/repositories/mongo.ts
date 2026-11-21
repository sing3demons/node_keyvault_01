import { MongoClient, ObjectId, type Collection, type Db, type Document } from "mongodb";
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
} from "../repository.js";

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

/**
 * Ids are strings (UUID) now; documents written by the earlier Mongo-only version used ObjectId.
 * Match either form so existing users/passkeys keep working.
 */
const anyId = (id: string): string =>
  (/^[0-9a-f]{24}$/i.test(id) ? { $in: [id, new ObjectId(id)] } : id) as unknown as string;

const isDuplicate = (error: unknown) => (error as { code?: number }).code === 11000;

async function insert<T extends { id: string }>(col: Collection<Doc<T>>, value: T, what: string) {
  try {
    await col.insertOne(toDoc(value) as never);
  } catch (error) {
    if (isDuplicate(error)) throw new DuplicateKeyError(`${what} already exists`);
    throw error;
  }
}

/** MongoDB (native driver) implementation. Uses TTL indexes for expiry. */
export class MongoAuthRepository implements AuthRepository {
  private readonly users$: Collection<Doc<User>>;
  private readonly credentials$: Collection<Doc<WebAuthnCredential>>;
  private readonly challenges$: Collection<Doc<WebAuthnChallenge>>;
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
    this.users$ = db.collection("users");
    this.credentials$ = db.collection("webauthn_credentials");
    this.challenges$ = db.collection("webauthn_challenges");
    this.authRequests$ = db.collection("auth_requests");
    this.authCodes$ = db.collection("auth_codes");
    this.access$ = db.collection("access_tokens");
    this.refresh$ = db.collection("refresh_tokens");
  }

  readonly users = {
    create: (user: User) => insert(this.users$, user, "Username"),
    findById: async (id: string) => fromDoc<User>(await this.users$.findOne({ _id: anyId(id) })),
    findByUsername: async (username: string) => fromDoc<User>(await this.users$.findOne({ username })),
    updatePasswordHash: async (id: string, passwordHash: string) => {
      await this.users$.updateOne({ _id: anyId(id) }, { $set: { passwordHash } });
    }
  };

  readonly credentials = {
    create: (cred: WebAuthnCredential) => insert(this.credentials$, cred, "Passkey"),
    findByCredId: async (credId: string) => fromDoc<WebAuthnCredential>(await this.credentials$.findOne({ credId })),
    listByUser: async (userId: string) =>
      (await this.credentials$.find({ userId: anyId(userId) }).sort({ createdAt: 1 }).toArray()).map(
        (d) => fromDoc<WebAuthnCredential>(d)!
      ),
    recordUse: async (id: string, counter: number, usedAt: Date) => {
      await this.credentials$.updateOne({ _id: anyId(id) }, { $set: { counter, lastUsedAt: usedAt } });
    },
    delete: async (userId: string, id: string) => (await this.credentials$.deleteOne({ _id: anyId(id), userId: anyId(userId) })).deletedCount > 0
  };

  readonly challenges = {
    create: (c: WebAuthnChallenge) => insert(this.challenges$, c, "Challenge"),
    consume: async (id: string, type: WebAuthnChallenge["type"]) =>
      fromDoc<WebAuthnChallenge>(await this.challenges$.findOneAndDelete({ _id: id, type }))
  };

  readonly authRequests = {
    create: (r: AuthRequest) => insert(this.authRequests$, r, "Authorization request"),
    findActive: async (id: string, now: Date) =>
      fromDoc<AuthRequest>(await this.authRequests$.findOne({ _id: id, expiresAt: { $gt: now } })),
    consumeActive: async (id: string, now: Date) =>
      fromDoc<AuthRequest>(await this.authRequests$.findOneAndDelete({ _id: id, expiresAt: { $gt: now } }))
  };

  readonly authCodes = {
    create: (c: AuthCode) => insert(this.authCodes$, c, "Authorization code"),
    redeem: async (id: string) =>
      fromDoc<AuthCode>(await this.authCodes$.findOneAndUpdate({ _id: id, used: false }, { $set: { used: true } })),
    find: async (id: string) => fromDoc<AuthCode>(await this.authCodes$.findOne({ _id: id }))
  };

  readonly tokens = {
    createPair: async (access: AccessToken, refresh: RefreshToken) => {
      await Promise.all([insert(this.access$, access, "Access token"), insert(this.refresh$, refresh, "Refresh token")]);
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
    }
  };

  async init(): Promise<void> {
    const ttl = { expireAfterSeconds: 0 };
    await Promise.all([
      this.users$.createIndex({ username: 1 }, { unique: true }),
      this.credentials$.createIndex({ credId: 1 }, { unique: true }),
      this.credentials$.createIndex({ userId: 1 }),
      this.challenges$.createIndex({ expiresAt: 1 }, ttl),
      this.authRequests$.createIndex({ expiresAt: 1 }, ttl),
      this.authCodes$.createIndex({ expiresAt: 1 }, ttl),
      this.access$.createIndex({ expiresAt: 1 }, ttl),
      this.access$.createIndex({ familyId: 1 }),
      this.refresh$.createIndex({ expiresAt: 1 }, ttl),
      this.refresh$.createIndex({ familyId: 1 })
    ]);
  }

  async purgeExpired(): Promise<void> {
    // TTL indexes handle expiry
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}
