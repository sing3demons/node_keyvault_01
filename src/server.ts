import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { config } from "./config.js";
import { KeyVaultService } from "./keyvault/service.js";
import { KeyVaultHandler } from "./keyvault/handle.js";
import { AzureKeyVaultSecretStore } from "./keyvault/store.js";

async function main() {
  const azureVaultUrl: string = process.env.AZURE_KEYVAULT_URL as string;
  const keyVaultSecretStore = new AzureKeyVaultSecretStore(azureVaultUrl);
  const keyVaultSecret = new KeyVaultService(keyVaultSecretStore);
  const keyVaultHandler = new KeyVaultHandler(keyVaultSecret);

  const app = new Hono();

  app.onError((error, c) => {
    let statusCode: ContentfulStatusCode = 500;
    if (typeof error === "object" && error !== null && "statusCode" in error) {
      const code = (error as { statusCode?: unknown }).statusCode;
      if (typeof code === "number" && code >= 400 && code < 600) {
        statusCode = code as ContentfulStatusCode;
      }
    }
    return c.json(
      {
        message: error instanceof Error ? error.message : "Unknown error"
      },
      statusCode
    );
  });

  app.get("/health", (c) => c.json({ status: "ok" }));

  app.get("/secrets", keyVaultHandler.getSecrets.bind(keyVaultHandler));

  app.get("/secrets/:name", keyVaultHandler.getSecret.bind(keyVaultHandler));

  app.put("/secrets/:name", keyVaultHandler.setSecret.bind(keyVaultHandler));

  app.delete("/secrets/:name", keyVaultHandler.deleteSecret.bind(keyVaultHandler));

  // React UI (built by `vite build` into dist/public)
  app.use("/*", serveStatic({ root: "./dist/public" }));

  serve({ fetch: app.fetch, port: config.port }, (info) => {
    console.log(`Server is running on port ${info.port}`);
  });
}

main();