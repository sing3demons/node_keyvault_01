import dotenv from "dotenv";

dotenv.config();

const list = (value: string | undefined, fallback: string[]): string[] =>
  value
    ? value
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : fallback;

class Config {
  port: number;
  azureVaultUrl?: string;

  /** Auth storage backend: "mongo" (native driver) | "postgres" (Drizzle ORM) */
  authDb: "mongo" | "postgres";
  mongoUrl: string;
  mongoDb: string;
  databaseUrl?: string;
  migrationsFolder: string;

  webauthn: {
    rpId: string;
    rpName: string;
    origins: string[];
  };

  oauth: {
    clientId: string;
    redirectUris: string[];
    accessTokenTtlSec: number;
    refreshTokenTtlSec: number;
  };

  /** Usernames that get the admin role (at startup for existing users, at registration for new ones). */
  adminUsernames: string[];

  oidc: {
    issuer: string;
    idTokenTtlSec: number;
    /** Key Vault secret holding the signing key set (hidden from the /secrets API). */
    keysSecretName: string;
    keyRotationDays: number;
    retiredKeyGraceSec: number;
    /** How often each instance reloads the key set (and rotates if due). */
    keysSyncSec: number;
  };

  constructor() {
    this.port = Number(process.env.PORT ?? "3001");
    this.azureVaultUrl = process.env.AZURE_KEYVAULT_URL;

    const authDb = (process.env.AUTH_DB ?? "mongo").toLowerCase();
    if (authDb !== "mongo" && authDb !== "postgres") {
      throw new Error(`AUTH_DB must be "mongo" or "postgres", got "${authDb}"`);
    }
    this.authDb = authDb;
    this.databaseUrl = process.env.DATABASE_URL;
    this.migrationsFolder = process.env.DRIZZLE_MIGRATIONS ?? "./drizzle";
    this.mongoUrl = process.env.MONGO_URL ?? "mongodb://localhost:27017";
    this.mongoDb = process.env.MONGO_DB ?? "keyvault";

    this.webauthn = {
      rpId: process.env.WEBAUTHN_RP_ID ?? "localhost",
      rpName: process.env.WEBAUTHN_RP_NAME ?? "Key Vault",
      origins: list(process.env.WEBAUTHN_ORIGINS, [
        "http://localhost:5173",
        `http://localhost:${this.port}`
      ])
    };

    this.oauth = {
      clientId: process.env.OAUTH_CLIENT_ID ?? "keyvault-web",
      redirectUris: list(process.env.OAUTH_REDIRECT_URIS, [
        "http://localhost:5173/callback",
        `http://localhost:${this.port}/callback`
      ]),
      accessTokenTtlSec: Number(process.env.ACCESS_TOKEN_TTL ?? 900),
      refreshTokenTtlSec: Number(process.env.REFRESH_TOKEN_TTL ?? 60 * 60 * 24 * 30)
    };

    this.adminUsernames = list(process.env.ADMIN_USERNAMES, []).map((u) => u.toLowerCase());

    this.oidc = {
      issuer: process.env.OIDC_ISSUER ?? `http://localhost:${this.port}`,
      idTokenTtlSec: Number(process.env.ID_TOKEN_TTL ?? 900),
      keysSecretName: process.env.OIDC_KEYS_SECRET ?? "oidc-signing-keys",
      keyRotationDays: Number(process.env.OIDC_KEY_ROTATION_DAYS ?? 30),
      retiredKeyGraceSec: Number(process.env.OIDC_RETIRED_KEY_GRACE_SEC ?? 24 * 60 * 60),
      keysSyncSec: Number(process.env.OIDC_KEYS_SYNC_SEC ?? 300)
    };
  }
}

export const config = new Config();
