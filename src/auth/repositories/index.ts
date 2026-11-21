import type { AuthRepository } from "../repository.js";

export type AuthDbDriver = "mongo" | "postgres";

export interface AuthDbSettings {
  driver: AuthDbDriver;
  mongoUrl: string;
  mongoDb: string;
  databaseUrl?: string;
  migrationsFolder: string;
}

/** Picks the storage backend from config. Drivers are imported lazily so only the selected one loads. */
export async function createAuthRepository(s: AuthDbSettings): Promise<AuthRepository> {
  switch (s.driver) {
    case "mongo": {
      const { MongoAuthRepository } = await import("./mongo/index.js");
      return MongoAuthRepository.connect(s.mongoUrl, s.mongoDb);
    }
    case "postgres": {
      if (!s.databaseUrl) throw new Error("DATABASE_URL is required when AUTH_DB=postgres");
      const { DrizzleAuthRepository } = await import("./drizzle/index.js");
      return DrizzleAuthRepository.connect(s.databaseUrl, s.migrationsFolder);
    }
    default:
      throw new Error(`Unsupported AUTH_DB "${String(s.driver)}" (use mongo | postgres)`);
  }
}
