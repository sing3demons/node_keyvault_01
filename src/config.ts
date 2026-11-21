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

  mongoUrl: string;
  mongoDb: string;

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

  constructor() {
    this.port = Number(process.env.PORT ?? "3001");
    this.azureVaultUrl = process.env.AZURE_KEYVAULT_URL;

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
  }
}

export const config = new Config();
