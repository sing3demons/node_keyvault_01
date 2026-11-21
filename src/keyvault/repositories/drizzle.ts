import { eq, inArray, and } from "drizzle-orm";
import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";
import { SecretAclExistsError, type Permission, type SecretAcl, type SecretAclRepository } from "../acl.js";
import * as schema from "./drizzle-schema.js";

const { secretAcls, secretGrants } = schema;

/** PostgreSQL (Drizzle) storage for secret ACLs. Shares the ./drizzle migrations folder with auth. */
export class DrizzleSecretAclRepository implements SecretAclRepository {
  private readonly db: NodePgDatabase<typeof schema>;

  static connect(connectionString: string, migrationsFolder: string): DrizzleSecretAclRepository {
    return new DrizzleSecretAclRepository(new Pool({ connectionString }), migrationsFolder);
  }

  constructor(
    private readonly pool: Pool,
    private readonly migrationsFolder: string
  ) {
    this.db = drizzle(pool, { schema });
  }

  async create(acl: SecretAcl): Promise<void> {
    try {
      await this.db.insert(secretAcls).values({ name: acl.name, ownerId: acl.ownerId, createdAt: acl.createdAt });
    } catch (error) {
      const e = error as { code?: string; cause?: { code?: string } };
      if (e.code === "23505" || e.cause?.code === "23505") throw new SecretAclExistsError(acl.name);
      throw error;
    }
  }

  async find(name: string): Promise<SecretAcl | null> {
    return (await this.findMany([name]))[0] ?? null;
  }

  async findMany(names: string[]): Promise<SecretAcl[]> {
    if (names.length === 0) return [];
    const [acls, grants] = await Promise.all([
      this.db.select().from(secretAcls).where(inArray(secretAcls.name, names)),
      this.db.select().from(secretGrants).where(inArray(secretGrants.secretName, names))
    ]);
    return acls.map((a) => ({
      name: a.name,
      ownerId: a.ownerId,
      createdAt: a.createdAt,
      grants: grants.filter((g) => g.secretName === a.name).map((g) => ({ userId: g.userId, permissions: g.permissions }))
    }));
  }

  async setGrant(name: string, userId: string, permissions: Permission[]): Promise<void> {
    if (permissions.length === 0) {
      await this.db.delete(secretGrants).where(and(eq(secretGrants.secretName, name), eq(secretGrants.userId, userId)));
      return;
    }
    await this.db
      .insert(secretGrants)
      .values({ secretName: name, userId, permissions })
      .onConflictDoUpdate({ target: [secretGrants.secretName, secretGrants.userId], set: { permissions } });
  }

  async setOwner(name: string, ownerId: string): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.update(secretAcls).set({ ownerId }).where(eq(secretAcls.name, name));
      await tx.delete(secretGrants).where(and(eq(secretGrants.secretName, name), eq(secretGrants.userId, ownerId)));
    });
  }

  async delete(name: string): Promise<void> {
    await this.db.delete(secretAcls).where(eq(secretAcls.name, name)); // grants cascade
  }

  async init(): Promise<void> {
    await migrate(this.db, { migrationsFolder: this.migrationsFolder });
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
