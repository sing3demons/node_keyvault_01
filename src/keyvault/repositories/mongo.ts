import { MongoClient, type Collection } from "mongodb";
import { SecretAclExistsError, type Permission, type SecretAcl, type SecretAclRepository } from "../acl.js";

type AclDoc = Omit<SecretAcl, "name"> & { _id: string };

/** secret_acls: one document per secret, `_id` = lowercased name, grants embedded. */
export class MongoSecretAclRepository implements SecretAclRepository {
  private readonly acls: Collection<AclDoc>;

  static async connect(url: string, dbName: string): Promise<MongoSecretAclRepository> {
    const client = new MongoClient(url);
    await client.connect();
    return new MongoSecretAclRepository(client, client.db(dbName).collection("secret_acls"));
  }

  constructor(
    private readonly client: MongoClient,
    acls: Collection<AclDoc>
  ) {
    this.acls = acls;
  }

  async create(acl: SecretAcl): Promise<void> {
    try {
      await this.acls.insertOne({ _id: acl.name, ownerId: acl.ownerId, grants: acl.grants, createdAt: acl.createdAt });
    } catch (error) {
      if ((error as { code?: number }).code === 11000) throw new SecretAclExistsError(acl.name);
      throw error;
    }
  }

  async find(name: string): Promise<SecretAcl | null> {
    return this.fromDoc(await this.acls.findOne({ _id: name }));
  }

  async findMany(names: string[]): Promise<SecretAcl[]> {
    if (names.length === 0) return [];
    return (await this.acls.find({ _id: { $in: names } }).toArray()).map((d) => this.fromDoc(d)!);
  }

  async setGrant(name: string, userId: string, permissions: Permission[]): Promise<void> {
    if (permissions.length === 0) {
      await this.acls.updateOne({ _id: name }, { $pull: { grants: { userId } } });
      return;
    }
    const updated = await this.acls.updateOne({ _id: name, "grants.userId": userId }, { $set: { "grants.$.permissions": permissions } });
    if (updated.matchedCount === 0) {
      // `$ne` keeps two concurrent first grants for the same user from both pushing
      await this.acls.updateOne({ _id: name, "grants.userId": { $ne: userId } }, { $push: { grants: { userId, permissions } } });
    }
  }

  async setOwner(name: string, ownerId: string): Promise<void> {
    await this.acls.updateOne({ _id: name }, { $set: { ownerId }, $pull: { grants: { userId: ownerId } } });
  }

  async delete(name: string): Promise<void> {
    await this.acls.deleteOne({ _id: name });
  }

  async init(): Promise<void> {
    await this.acls.createIndex({ ownerId: 1 });
  }

  async close(): Promise<void> {
    await this.client.close();
  }

  private fromDoc(doc: AclDoc | null): SecretAcl | null {
    if (!doc) return null;
    return {
      name: doc._id,
      ownerId: doc.ownerId,
      grants: (doc.grants ?? []).map((g) => ({ userId: g.userId, permissions: [...g.permissions] })),
      createdAt: doc.createdAt
    };
  }
}
