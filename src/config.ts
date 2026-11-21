import dotenv from "dotenv";

dotenv.config();

export type SecretProvider = "azure" | "local";

const secretProvider = (process.env.SECRET_PROVIDER ?? "local") as SecretProvider;

if (secretProvider !== "azure" && secretProvider !== "local") {
  throw new Error(`SECRET_PROVIDER must be "azure" or "local". Received: ${process.env.SECRET_PROVIDER}`);
}

export const config = {
  port: Number(process.env.PORT ?? "3000"),
  secretProvider,
  azureVaultUrl: process.env.AZURE_KEYVAULT_URL,
  localVaultAddr: process.env.LOCAL_VAULT_ADDR ?? "http://vault:8200",
  localVaultToken: process.env.LOCAL_VAULT_TOKEN ?? "root"
};
