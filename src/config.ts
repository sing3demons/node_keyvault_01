import dotenv from "dotenv";
import { parseMasterEnv, type MasterEnv } from "./auth/master-account.js";

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

  /**
   * OAuth clients live in the database (UI: Clients, API: /admin/clients). Only the built-in client the
   * React UI uses is created from these values, on first start; afterwards it is edited like any other.
   * The old env vars (OAUTH_CLIENT_ID, OAUTH_REDIRECT_URIS, ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL, ID_TOKEN_TTL,
   * EMAIL_VERIFICATION) are still read here, so existing setups seed the same client they had.
   */
  defaultClient: {
    id: string;
    redirectUris: string[];
    emailVerification: "code" | "link";
  };
  /** Lifetimes for clients that do not set their own (and for the built-in client). */
  clientDefaults: {
    accessTokenTtlSec: number;
    refreshTokenTtlSec: number;
    idTokenTtlSec: number;
  };

  mail: {
    /** Unset => emails are printed to the log (development only). */
    smtpUrl?: string;
    from: string;
  };

  emailCodes: {
    ttlSec: number;
    maxAttempts: number;
    resendCooldownSec: number;
    maxSends: number;
  };

  /** MASTER_CREDENTIALS: manages OAuth clients and their owners (UI /manage, or /auth/master/* then Bearer). */
  master: MasterEnv | null;
  /** MASTER_EMAIL_VERIFICATION: otp (6-digit code, default) | link — the master sign-in's email step. */
  masterEmailVerification: "code" | "link";

  /** Take the client IP from X-Forwarded-For (only behind a reverse proxy you control). */
  trustProxy: boolean;

  /** Usernames that get the admin role (at startup for existing users, at registration for new ones). */
  adminUsernames: string[];

  oidc: {
    issuer: string;
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

    const method = (process.env.EMAIL_VERIFICATION ?? "code").toLowerCase();
    if (method !== "code" && method !== "link") {
      throw new Error(`EMAIL_VERIFICATION must be "code" or "link", got "${method}"`);
    }
    this.defaultClient = {
      id: process.env.OAUTH_CLIENT_ID ?? "keyvault-web",
      redirectUris: list(process.env.OAUTH_REDIRECT_URIS, this.webauthn.origins.map((o) => `${o}/callback`)),
      emailVerification: method
    };
    this.clientDefaults = {
      accessTokenTtlSec: Number(process.env.ACCESS_TOKEN_TTL ?? 900),
      refreshTokenTtlSec: Number(process.env.REFRESH_TOKEN_TTL ?? 60 * 60 * 24 * 30),
      idTokenTtlSec: Number(process.env.ID_TOKEN_TTL ?? 900)
    };

    this.mail = {
      smtpUrl: process.env.SMTP_URL || undefined,
      from: process.env.MAIL_FROM ?? `${this.webauthn.rpName} <no-reply@localhost>`
    };

    this.emailCodes = {
      ttlSec: Number(process.env.EMAIL_CODE_TTL ?? 600),
      maxAttempts: Number(process.env.EMAIL_CODE_MAX_ATTEMPTS ?? 5),
      resendCooldownSec: Number(process.env.EMAIL_CODE_RESEND_COOLDOWN ?? 30),
      maxSends: Number(process.env.EMAIL_CODE_MAX_SENDS ?? 5)
    };

    this.master = parseMasterEnv("MASTER_CREDENTIALS", process.env.MASTER_CREDENTIALS);
    const masterVerification = (process.env.MASTER_EMAIL_VERIFICATION ?? "otp").trim().toLowerCase();
    if (!["otp", "code", "link"].includes(masterVerification)) {
      throw new Error(`MASTER_EMAIL_VERIFICATION must be "otp" or "link", got "${masterVerification}"`);
    }
    this.masterEmailVerification = masterVerification === "link" ? "link" : "code";

    this.trustProxy = /^(1|true|yes)$/i.test(process.env.TRUST_PROXY ?? "");

    this.adminUsernames = list(process.env.ADMIN_USERNAMES, []).map((u) => u.toLowerCase());

    this.oidc = {
      issuer: process.env.OIDC_ISSUER ?? `http://localhost:${this.port}`,
      keysSecretName: process.env.OIDC_KEYS_SECRET ?? "oidc-signing-keys",
      keyRotationDays: Number(process.env.OIDC_KEY_ROTATION_DAYS ?? 30),
      retiredKeyGraceSec: Number(process.env.OIDC_RETIRED_KEY_GRACE_SEC ?? 24 * 60 * 60),
      keysSyncSec: Number(process.env.OIDC_KEYS_SYNC_SEC ?? 300)
    };
  }
}

export const config = new Config();
