import type { SecretAclRepository } from "../acl.js";

export interface AclDbSettings {
  driver: "mongo" | "postgres";
  mongoUrl: string;
  mongoDb: string;
  databaseUrl?: string;
  migrationsFolder: string;
}

/** Same backend as the auth data (AUTH_DB); drivers load lazily. */
export async function createSecretAclRepository(s: AclDbSettings): Promise<SecretAclRepository> {
  if (s.driver === "mongo") {
    const { MongoSecretAclRepository } = await import("./mongo.js");
    return MongoSecretAclRepository.connect(s.mongoUrl, s.mongoDb);
  }
  if (!s.databaseUrl) throw new Error("DATABASE_URL is required when AUTH_DB=postgres");
  const { DrizzleSecretAclRepository } = await import("./drizzle.js");
  return DrizzleSecretAclRepository.connect(s.databaseUrl, s.migrationsFolder);
}
