import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import { config } from "./config.js";
import { errorHandler, notFoundHandler } from "./shared/http.js";
import { KeyVaultService } from "./keyvault/service.js";
import { KeyVaultController } from "./keyvault/controller.js";
import { AzureKeyVaultSecretStore, NamedSecret } from "./keyvault/store.js";
import { createSecretAclRepository } from "./keyvault/repositories/index.js";
import { createAuthRepository } from "./auth/repositories/index.js";
import { AuthService, SUPPORTED_SCOPES } from "./auth/service.js";
import { ClientService } from "./auth/clients.js";
import { IdTokenIssuer, SigningKeyRing } from "./auth/oidc.js";
import { Argon2idHasher, SecretHasher } from "./shared/hashing.js";
import { WebAuthnService } from "./auth/webauthn.js";
import { EmailCodeService } from "./auth/email-codes.js";
import { DeviceService } from "./auth/devices.js";
import { createMailer } from "./shared/mail.js";
import { AuthController } from "./auth/controller.js";
import { MasterCredential, requireAuth, requireRole, requireRoleOrMaster, type AuthEnv } from "./shared/middleware.js";

async function main() {
  const azureVaultUrl: string = process.env.AZURE_KEYVAULT_URL as string;
  const keyVaultSecretStore = new AzureKeyVaultSecretStore(azureVaultUrl);
  const dbSettings = {
    driver: config.authDb,
    mongoUrl: config.mongoUrl,
    mongoDb: config.mongoDb,
    databaseUrl: config.databaseUrl,
    migrationsFolder: config.migrationsFolder
  };
  const authRepo = await createAuthRepository(dbSettings);
  await authRepo.init();

  // Secrets: values in Key Vault, ownership/sharing in the app database
  const secretAcls = await createSecretAclRepository(dbSettings);
  await secretAcls.init();
  const userDirectory = {
    findByUsername: async (username: string) => {
      const u = await authRepo.users.findByUsername(username);
      return u && { id: u.id, username: u.username };
    },
    findByIds: async (ids: string[]) =>
      (await Promise.all(ids.map((id) => authRepo.users.findById(id)))).flatMap((u) => (u ? [{ id: u.id, username: u.username }] : []))
  };
  const keyVaultSecret = new KeyVaultService(keyVaultSecretStore, secretAcls, userDirectory, [config.oidc.keysSecretName]);
  const keyVaultHandler = new KeyVaultController(keyVaultSecret);
  // OIDC signing keys live in Key Vault
  const signingKeys = new SigningKeyRing(new NamedSecret(keyVaultSecretStore, config.oidc.keysSecretName), config.oidc);
  await signingKeys.init();
  const idTokens = new IdTokenIssuer(config.oidc, signingKeys);
  // OAuth clients (RFC 7591 metadata + per-client token lifetimes / email method) live in the auth DB
  const clients = new ClientService(authRepo, {
    defaults: config.clientDefaults,
    maxIdTokenTtlSec: config.oidc.retiredKeyGraceSec,
    supportedScopes: SUPPORTED_SCOPES
  });
  await clients.seed({
    id: config.defaultClient.id,
    name: config.webauthn.rpName,
    tokenEndpointAuthMethod: "none", // the React UI is a public client (PKCE)
    redirectUris: config.defaultClient.redirectUris,
    grantTypes: ["authorization_code", "refresh_token"],
    scope: [...SUPPORTED_SCOPES].sort().join(" "),
    // emailed sign-in links send the browser here; the UI then starts a fresh sign-in
    initiateLoginUri: `${new URL(config.defaultClient.redirectUris[0]!).origin}/`,
    ...config.clientDefaults,
    idTokenTtlSec: Math.min(config.clientDefaults.idTokenTtlSec, config.oidc.retiredKeyGraceSec),
    emailVerification: config.defaultClient.emailVerification
  });
  const emailCodes = new EmailCodeService(
    authRepo,
    createMailer(config.mail),
    { ...config.emailCodes, appName: config.webauthn.rpName },
    async (clientId) => (await clients.find(clientId))?.name
  );
  const authService = new AuthService(
    authRepo,
    new SecretHasher(new Argon2idHasher()),
    clients,
    idTokens,
    emailCodes,
    new DeviceService(authRepo),
    config.adminUsernames
  );
  await authService.bootstrapAdmins();
  const webAuthnService = new WebAuthnService(authRepo, config.webauthn);
  const auth = new AuthController(authService, webAuthnService, idTokens, clients, config.webauthn.origins, config.trustProxy);
  const bearer = requireAuth(authService);

  const app = new Hono<AuthEnv>();

  app.onError(errorHandler);
  app.notFound(notFoundHandler);

  app.get("/health", (c) => c.json({ status: "ok" }));

  // --- OpenID Connect discovery
  app.get("/.well-known/openid-configuration", (c) => auth.openidConfiguration(c));
  app.get("/.well-known/jwks.json", (c) => auth.jwks(c));

  // --- OAuth2 Authorization Server (Authorization Code + PKCE, opaque tokens; ID Token with "openid")
  app.get("/oauth/authorize", (c) => auth.authorize(c));
  app.post("/oauth/token", (c) => auth.token(c));
  app.post("/oauth/revoke", (c) => auth.revoke(c));
  app.get("/oauth/userinfo", bearer, (c) => auth.userinfo(c));

  // --- Authentication used by the login page (password = argon2id, passkey = fido2-lib)
  app.post("/auth/register", (c) => auth.register(c));
  app.get("/auth/me", bearer, (c) => auth.getAccount(c));
  app.patch("/auth/me", bearer, (c) => auth.updateAccount(c));
  app.post("/auth/login/password", (c) => auth.loginPassword(c));
  // emailed codes: registration, sign-in with an email address, verifying an address
  app.post("/auth/email/verify", (c) => auth.confirmEmailCode(c));
  app.post("/auth/email/resend", (c) => auth.resendEmailCode(c));
  app.post("/auth/email/link", (c) => auth.openEmailLink(c)); // clients with email_verification=link
  app.post("/auth/email/link/resume", (c) => auth.resumeEmailLink(c));
  app.post("/auth/email/status", (c) => auth.emailChallengeStatus(c));
  app.post("/auth/me/email/verification", bearer, (c) => auth.startEmailVerification(c));
  // devices the user signed in from
  app.get("/auth/me/devices", bearer, (c) => auth.listDevices(c));
  app.post("/auth/me/devices/:id/sign-out", bearer, (c) => auth.signOutDevice(c));
  app.delete("/auth/me/devices/:id", bearer, (c) => auth.removeDevice(c));
  app.post("/auth/webauthn/login/options", (c) => auth.passkeyLoginOptions(c));
  app.post("/auth/webauthn/login/verify", (c) => auth.passkeyLoginVerify(c));

  // --- Passkey management for the signed-in user
  app.post("/auth/webauthn/register/options", bearer, (c) => auth.passkeyRegisterOptions(c));
  app.post("/auth/webauthn/register/verify", bearer, (c) => auth.passkeyRegisterVerify(c));
  app.get("/auth/webauthn/credentials", bearer, (c) => auth.listPasskeys(c));
  app.delete("/auth/webauthn/credentials/:id", bearer, (c) => auth.deletePasskey(c));

  // --- Administration
  app.use("/admin/users", bearer, requireRole("admin"));
  app.use("/admin/users/*", bearer, requireRole("admin"));
  app.get("/admin/users", (c) => auth.listUsers(c));
  app.put("/admin/users/:username/roles", (c) => auth.setUserRoles(c));
  // OAuth clients (RFC 7591 metadata; RFC 7592-style read / update / delete):
  // an admin user's Bearer token, or the master credential (MASTER_CREDENTIALS) as HTTP Basic
  const clientAdmin = requireRoleOrMaster(authService, "admin", config.master);
  app.use("/admin/clients", clientAdmin);
  app.use("/admin/clients/*", clientAdmin);
  app.get("/admin/clients", (c) => auth.listClients(c));
  app.post("/admin/clients", (c) => auth.registerClient(c));
  app.get("/admin/clients/:id", (c) => auth.getClient(c));
  app.put("/admin/clients/:id", (c) => auth.updateClient(c));
  app.delete("/admin/clients/:id", (c) => auth.deleteClient(c));
  app.post("/admin/clients/:id/secret", (c) => auth.rotateClientSecret(c));

  // --- Secrets (protected)
  app.use("/secrets", bearer);
  app.use("/secrets/*", bearer);

  app.get("/secrets", keyVaultHandler.getSecrets.bind(keyVaultHandler));

  app.get("/secrets/:name", keyVaultHandler.getSecret.bind(keyVaultHandler));

  app.put("/secrets/:name", keyVaultHandler.setSecret.bind(keyVaultHandler));

  app.delete("/secrets/:name", keyVaultHandler.deleteSecret.bind(keyVaultHandler));

  // sharing (owner only)
  app.get("/secrets/:name/grants", (c) => keyVaultHandler.getGrants(c));
  app.put("/secrets/:name/grants/:username", (c) => keyVaultHandler.setGrant(c));
  app.delete("/secrets/:name/grants/:username", (c) => keyVaultHandler.deleteGrant(c));
  // ownership transfer (owner or admin)
  app.put("/secrets/:name/owner", (c) => keyVaultHandler.transferOwnership(c));

  // React UI (built by `vite build` into dist/public); client-side routes (/login, /callback) fall back to index.html
  app.use("/*", serveStatic({ root: "./dist/public" }));
  app.get("*", serveStatic({ path: "./dist/public/index.html" }));

  serve({ fetch: app.fetch, port: config.port }, (info) => {
    console.log(`Server is running on port ${info.port} (auth db: ${config.authDb})`);
  });
}

main();
