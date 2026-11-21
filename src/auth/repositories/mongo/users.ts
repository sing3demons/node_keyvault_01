// Users with their profiles and credentials embedded in one document.

import { randomUUID } from "node:crypto";
import { ObjectId, type Collection, type Db, type Document } from "mongodb";
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
import { DuplicateKeyError, type UserRepository } from "../../repository.js";
import { byId, duplicateError, idOf } from "./shared.js";

/**
 * Users are stored as one document with profiles and credentials embedded:
 *   { _id, username, email?, profiles: [{ lang, firstName, lastName }], preferredLang?, createdAt,
 *     credentials: [{ id, type, key, value?, algorithm?, webauthn?, createdAt, lastUsedAt? }] }
 * `key` is storage-only and backs a unique multikey index:
 *   "<secretType>:<userId>" (one password / pin / ... per user) | "webauthn:<credId>" (credId globally unique).
 * (A unique index on credentials.webauthn.credId would collide on the null produced by password entries.)
 */
type CredentialElement = Credential & { key: string };
export type UserDoc = Omit<User, "id" | "credentials"> & { _id: string; credentials: CredentialElement[] };

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
  return {
    id: idOf(doc._id),
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

export class MongoUserRepository implements UserRepository {
  private readonly users$: Collection<UserDoc>;

  constructor(private readonly db: Db) {
    this.users$ = db.collection("users");
  }

  async create(user: User): Promise<void> {
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
      throw duplicateError(error) ?? error;
    }
  }

  async updateAccount(userId: string, update: AccountUpdate): Promise<void> {
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
      await this.users$.updateOne({ _id: byId(userId) }, { $set, ...(Object.keys($unset).length ? { $unset } : {}) });
    } catch (error) {
      throw duplicateError(error) ?? error;
    }
  }

  async findById(id: string): Promise<User | null> {
    return userFromDoc(await this.users$.findOne({ _id: byId(id) }));
  }

  async list(): Promise<UserSummary[]> {
    const docs = await this.users$
      .find({}, { projection: { username: 1, email: 1, roles: 1, createdAt: 1 } })
      .sort({ createdAt: 1 })
      .toArray();
    return docs.map((d) => ({
      id: idOf(d._id),
      username: d.username,
      ...(typeof d.email === "string" ? { email: d.email } : {}),
      roles: Array.isArray(d.roles) ? d.roles : [],
      createdAt: d.createdAt
    }));
  }

  async setRoles(userId: string, roles: Role[]): Promise<void> {
    await this.users$.updateOne({ _id: byId(userId) }, { $set: { roles } });
  }

  async findByUsername(username: string): Promise<User | null> {
    return userFromDoc(await this.users$.findOne({ username }));
  }

  async findRefByUsername(username: string): Promise<UserRef | null> {
    const d = await this.users$.findOne({ username }, { projection: { username: 1 } });
    return d && { id: idOf(d._id), username: d.username };
  }

  async findRefs(ids: string[]): Promise<UserRef[]> {
    if (ids.length === 0) return [];
    // ids may be legacy ObjectIds (see byId)
    const keys = ids.flatMap((id) => (/^[0-9a-f]{24}$/i.test(id) ? [id, new ObjectId(id)] : [id]));
    const docs = await this.users$.find({ _id: { $in: keys as never[] } }, { projection: { username: 1 } }).toArray();
    return docs.map((d) => ({ id: idOf(d._id), username: d.username }));
  }

  async findByEmail(email: string): Promise<User | null> {
    return userFromDoc(await this.users$.findOne({ email }));
  }

  async markEmailVerified(userId: string, email: string, at: Date): Promise<boolean> {
    return (await this.users$.updateOne({ _id: byId(userId), email }, { $set: { emailVerifiedAt: at } })).matchedCount > 0;
  }

  async findByWebAuthnCredId(credId: string): Promise<{ user: User; credential: WebAuthnCredential } | null> {
    const user = userFromDoc(await this.users$.findOne({ "credentials.key": `webauthn:${credId}` }));
    const credential = user?.credentials.find((c): c is WebAuthnCredential => c.type === "webauthn" && c.webauthn.credId === credId);
    return user && credential ? { user, credential } : null;
  }

  async addCredential(userId: string, credential: Credential): Promise<void> {
    const element = toElement(userId, credential);
    try {
      // The unique index only spans documents; `$ne` also blocks a duplicate key inside this user's own array
      // (e.g. a second password, or the same passkey twice).
      const res = await this.users$.updateOne(
        { _id: byId(userId), "credentials.key": { $ne: element.key } },
        { $push: { credentials: element } }
      );
      if (res.matchedCount === 0 && (await this.users$.countDocuments({ _id: byId(userId) })) > 0) {
        throw new DuplicateKeyError("credential");
      }
    } catch (error) {
      throw duplicateError(error) ?? error;
    }
  }

  async updateSecret(userId: string, credentialId: string, value: string, algorithm: HashAlgorithm): Promise<void> {
    await this.users$.updateOne(
      { _id: byId(userId), "credentials.id": credentialId },
      { $set: { "credentials.$.value": value, "credentials.$.algorithm": algorithm } }
    );
  }

  async recordWebAuthnUse(userId: string, credentialId: string, counter: number, usedAt: Date): Promise<void> {
    await this.users$.updateOne(
      { _id: byId(userId), "credentials.id": credentialId },
      { $set: { "credentials.$.webauthn.counter": counter, "credentials.$.lastUsedAt": usedAt } }
    );
  }

  async removeCredential(userId: string, credentialId: string): Promise<"removed" | "not_found" | "last_credential"> {
    // single atomic update: only pull when at least 2 credentials exist
    const res = await this.users$.updateOne(
      { _id: byId(userId), "credentials.id": credentialId, "credentials.1": { $exists: true } },
      { $pull: { credentials: { id: credentialId } } }
    );
    if (res.modifiedCount > 0) return "removed";
    const exists = await this.users$.countDocuments({ _id: byId(userId), "credentials.id": credentialId });
    return exists ? "last_credential" : "not_found";
  }

  async ensureIndexes(): Promise<void> {
    await this.migrateLegacyUsers();
    await Promise.all([
      this.users$.createIndex({ username: 1 }, { unique: true }),
      // partial: accounts created before email was collected have none
      this.users$.createIndex({ email: 1 }, { unique: true, partialFilterExpression: { email: { $type: "string" } } }),
      this.users$.createIndex({ "credentials.key": 1 }, { unique: true, partialFilterExpression: { "credentials.key": { $exists: true } } })
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
      const userId = idOf(u._id);
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
      const userId = idOf(c.userId);
      const passkey: Credential = {
        id: idOf(c._id),
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
        { _id: byId(userId) as never, "credentials.key": { $ne: credentialKey(userId, passkey) } },
        { $push: { credentials: toElement(userId, passkey) } } as never
      );
      await oldCreds.deleteOne({ _id: c._id });
    }
    if ((await this.db.listCollections({ name: "webauthn_credentials" }).toArray()).length > 0) {
      if ((await oldCreds.countDocuments()) === 0) await oldCreds.drop();
    }
  }
}
