// Composition root: config -> storage -> modules -> routes -> HTTP server.

import { Kp, serve, serveStatic } from "./common/kp/index.js";
import { createAuthModule } from "./auth/index.js";
import { AuthUserDirectory } from "./auth/accounts/user-directory.js";
import { IdTokenIssuer, SigningKeyRing } from "./auth/oauth/oidc.js";
import { createAuthRepository } from "./auth/repositories/index.js";
import { config } from "./config.js";
import { KeyVaultController } from "./keyvault/controller.js";
import { createSecretAclRepository } from "./keyvault/repositories/index.js";
import { KeyVaultService } from "./keyvault/service.js";
import { AzureKeyVaultSecretStore, NamedSecret } from "./keyvault/store.js";
import { errorHandler, notFoundHandler } from "./shared/http.js";
import { Bearer } from "./shared/middleware.js";

async function main() {
  // --- storage
  const dbSettings = {
    driver: config.authDb,
    mongoUrl: config.mongoUrl,
    mongoDb: config.mongoDb,
    databaseUrl: config.databaseUrl,
    migrationsFolder: config.migrationsFolder
  };
  const authRepo = await createAuthRepository(dbSettings);
  await authRepo.init();
  const secretAcls = await createSecretAclRepository(dbSettings);
  await secretAcls.init();
  const vault = new AzureKeyVaultSecretStore(config.azureVaultUrl as string);

  // --- OIDC signing keys live in Key Vault (hidden from the /secrets API)
  const signingKeys = new SigningKeyRing(new NamedSecret(vault, config.oidc.keysSecretName), config.oidc);
  await signingKeys.init();
  const idTokens = new IdTokenIssuer(config.oidc, signingKeys);

  // --- modules
  const auth = await createAuthModule(config, authRepo, idTokens);
  const secrets = new KeyVaultController(
    new KeyVaultService(vault, secretAcls, new AuthUserDirectory(authRepo), [config.oidc.keysSecretName])
  );

  // --- routes
  const app = new Kp();
  app.onError(errorHandler);
  app.notFound(notFoundHandler);

  // public: says which secret store backs the API (shown in the UI header), nothing more
  app.get("/health", (c) => c.json({ status: "ok", provider: "Azure Key Vault" }));
  auth.registerRoutes(app);
  app.provide(Bearer, new Bearer(auth.oauth)); // for @UseInterceptors(Bearer)
  app.register(secrets);

  // React UI (built by `vite build` into dist/public); client-side routes (/login, /callback) fall back to index.html
  app.use("/*", serveStatic({ root: "./dist/public" }));
  app.get("*", serveStatic({ path: "./dist/public/index.html" }));

  serve({ fetch: app.fetch, port: config.port }, (info) => {
    console.log(`Server is running on port ${info.port} (auth db: ${config.authDb})`);
  });
}

main();
