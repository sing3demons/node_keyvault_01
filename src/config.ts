import dotenv from "dotenv";

dotenv.config();

// AZURE_KEYVAULT_URL = https://primary.localhost:8443
// # DefaultAzureCredential -> ManagedIdentityCredential -> emulator's fake token endpoint
// IDENTITY_ENDPOINT = http://localhost:8080/metadata/identity/oauth2/token
// IDENTITY_HEADER = header
// # emulator uses a self - signed certificate(local dev only!)
// NODE_TLS_REJECT_UNAUTHORIZED = 0


class Config {
  port: number;
  azureVaultUrl?: string;

  constructor() {
    this.port = Number(process.env.PORT ?? "3001");
    this.azureVaultUrl = process.env.AZURE_KEYVAULT_URL;
  }
}

export const config = new Config();