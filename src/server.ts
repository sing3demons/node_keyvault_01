import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import { config } from "./config.js";
import { errorHandler, notFoundHandler } from "./shared/http.js";
import { KeyVaultService } from "./keyvault/service.js";
import { KeyVaultController } from "./keyvault/controller.js";
import { AzureKeyVaultSecretStore } from "./keyvault/store.js";
import { createAuthRepository } from "./auth/repositories/index.js";
import { AuthService } from "./auth/service.js";
import { Argon2idHasher, SecretHasher } from "./shared/hashing.js";
import { WebAuthnService } from "./auth/webauthn.js";
import { AuthController } from "./auth/controller.js";
import { requireAuth, type AuthEnv } from "./shared/middleware.js";

async function main() {
  const azureVaultUrl: string = process.env.AZURE_KEYVAULT_URL as string;
  const keyVaultSecretStore = new AzureKeyVaultSecretStore(azureVaultUrl);
  const keyVaultSecret = new KeyVaultService(keyVaultSecretStore);
  const keyVaultHandler = new KeyVaultController(keyVaultSecret);

  const authRepo = await createAuthRepository({
    driver: config.authDb,
    mongoUrl: config.mongoUrl,
    mongoDb: config.mongoDb,
    databaseUrl: config.databaseUrl,
    migrationsFolder: config.migrationsFolder
  });
  await authRepo.init();
  // RDBs have no TTL index: sweep expired codes/tokens/challenges periodically
  setInterval(() => authRepo.purgeExpired(new Date()).catch((e) => console.error("purgeExpired failed", e)), 10 * 60_000).unref();
  const authService = new AuthService(authRepo, new SecretHasher(new Argon2idHasher()), config.oauth);
  const webAuthnService = new WebAuthnService(authRepo, config.webauthn);
  const auth = new AuthController(authService, webAuthnService);
  const bearer = requireAuth(authService);

  const app = new Hono<AuthEnv>();

  app.onError(errorHandler);
  app.notFound(notFoundHandler);

  app.get("/health", (c) => c.json({ status: "ok" }));

  // --- OAuth2 Authorization Server (Authorization Code + PKCE, opaque tokens)
  app.get("/oauth/authorize", (c) => auth.authorize(c));
  app.post("/oauth/token", (c) => auth.token(c));
  app.post("/oauth/revoke", (c) => auth.revoke(c));
  app.get("/oauth/userinfo", bearer, (c) => auth.userinfo(c));

  // --- Authentication used by the login page (password = argon2id, passkey = fido2-lib)
  app.post("/auth/register", (c) => auth.register(c));
  app.get("/auth/me", bearer, (c) => auth.getAccount(c));
  app.patch("/auth/me", bearer, (c) => auth.updateAccount(c));
  app.post("/auth/login/password", (c) => auth.loginPassword(c));
  app.post("/auth/webauthn/login/options", (c) => auth.passkeyLoginOptions(c));
  app.post("/auth/webauthn/login/verify", (c) => auth.passkeyLoginVerify(c));

  // --- Passkey management for the signed-in user
  app.post("/auth/webauthn/register/options", bearer, (c) => auth.passkeyRegisterOptions(c));
  app.post("/auth/webauthn/register/verify", bearer, (c) => auth.passkeyRegisterVerify(c));
  app.get("/auth/webauthn/credentials", bearer, (c) => auth.listPasskeys(c));
  app.delete("/auth/webauthn/credentials/:id", bearer, (c) => auth.deletePasskey(c));

  // --- Secrets (protected)
  app.use("/secrets", bearer);
  app.use("/secrets/*", bearer);

  app.get("/secrets", keyVaultHandler.getSecrets.bind(keyVaultHandler));

  app.get("/secrets/:name", keyVaultHandler.getSecret.bind(keyVaultHandler));

  app.put("/secrets/:name", keyVaultHandler.setSecret.bind(keyVaultHandler));

  app.delete("/secrets/:name", keyVaultHandler.deleteSecret.bind(keyVaultHandler));

  // React UI (built by `vite build` into dist/public); client-side routes (/login, /callback) fall back to index.html
  app.use("/*", serveStatic({ root: "./dist/public" }));
  app.get("*", serveStatic({ path: "./dist/public/index.html" }));

  serve({ fetch: app.fetch, port: config.port }, (info) => {
    console.log(`Server is running on port ${info.port} (auth db: ${config.authDb})`);
  });
}

main();
