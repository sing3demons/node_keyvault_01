// The auth module: builds every auth service from config and registers all of its routes.
//
//   oauth/     authorization requests, tokens, revoke, introspect, UserInfo, discovery
//   sign-in/   register, password / passkey sign-in, the emailed code / link step
//   accounts/  users: profile (/auth/me), roles (/admin/users), password check
//   email/     one-time codes and links sent by email
//   devices/   browsers a user signed in from
//   webauthn/  passkeys
//   clients/   OAuth clients and their owners (/admin/clients, /admin/client-owners)
//   master/    the master account (bootstrap admin of clients) and its sign-in
//   password/  forgot password (emailed code / link -> new password), change password (signed in)

import type { Hono, MiddlewareHandler } from "hono";
import type { AppConfig } from "../config.js";
import { Argon2idHasher, SecretHasher } from "../shared/hashing.js";
import { createMailer } from "../shared/mail.js";
import { requireAuth, requireRoleOrMaster, type AuthEnv } from "../shared/middleware.js";
import { registerAccountRoutes } from "./accounts/routes.js";
import { AccountService } from "./accounts/service.js";
import { ClientService } from "./clients/clients.js";
import { ClientOwnerService } from "./clients/owners.js";
import { registerClientRoutes } from "./clients/routes.js";
import { DeviceService } from "./devices/devices.js";
import { registerDeviceRoutes } from "./devices/routes.js";
import { EmailCodeService } from "./email/email-codes.js";
import { RequestContext } from "./http.js";
import { MasterAccountStore, type SyncResult } from "./master/account.js";
import { MasterAuthService } from "./master/auth.js";
import { registerMasterRoutes } from "./master/routes.js";
import type { IdTokenIssuer } from "./oauth/oidc.js";
import { registerOAuthRoutes } from "./oauth/routes.js";
import { OAuthService, SUPPORTED_SCOPES } from "./oauth/service.js";
import type { AuthRepository } from "./repository.js";
import { registerPasswordRoutes } from "./password/routes.js";
import { PasswordService } from "./password/service.js";
import { registerSignInRoutes } from "./sign-in/routes.js";
import { SignInService } from "./sign-in/service.js";
import { registerPasskeyRoutes } from "./webauthn/routes.js";
import { WebAuthnService } from "./webauthn/webauthn.js";

export interface AuthModule {
  /** Resolves Bearer tokens (for any module's protected routes). */
  oauth: OAuthService;
  /** requireAuth middleware: a user's access token. */
  bearer: MiddlewareHandler<AuthEnv>;
  registerRoutes(app: Hono<AuthEnv>): void;
}

const MASTER_SYNC_NOTE: Record<SyncResult, string> = {
  created: "created from MASTER_CREDENTIALS",
  kept: "matches MASTER_CREDENTIALS (kept)",
  replaced: "MASTER_CREDENTIALS changed — replaced, old master sessions ended",
  stored: "using the stored account (MASTER_CREDENTIALS is empty)",
  none: "none"
};

export async function createAuthModule(config: AppConfig, repo: AuthRepository, idTokens: IdTokenIssuer): Promise<AuthModule> {
  // OAuth clients (RFC 7591 metadata + per-client token lifetimes / email method / sender) live in the auth DB
  const clients = new ClientService(repo, {
    defaults: config.clientDefaults,
    maxIdTokenTtlSec: config.oidc.retiredKeyGraceSec,
    supportedScopes: SUPPORTED_SCOPES,
    defaultMailFrom: config.mail.from
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

  // master account: stored in the DB, made to match MASTER_CREDENTIALS on every start
  const masterAccounts = new MasterAccountStore(repo);
  console.log(`Master account: ${MASTER_SYNC_NOTE[await masterAccounts.syncFromEnv(config.master)]}`);
  const owners = new ClientOwnerService(repo, masterAccounts);

  const emailCodes = new EmailCodeService(
    repo,
    createMailer(config.mail),
    { ...config.emailCodes, appName: config.webauthn.rpName },
    async (clientId) => {
      const c = await clients.find(clientId);
      return c ? { name: c.name, ...(c.mailFrom ? { mailFrom: c.mailFrom } : {}) } : undefined;
    }
  );
  const devices = new DeviceService(repo);
  const oauth = new OAuthService(repo, clients, idTokens, devices);
  const accounts = new AccountService(repo, new SecretHasher(new Argon2idHasher()), config.adminUsernames);
  await accounts.bootstrapAdmins();
  const signIn = new SignInService(repo, oauth, accounts, clients, emailCodes);
  const passwords = new PasswordService(repo, oauth, accounts, clients, emailCodes);
  const masterAuth = new MasterAuthService(repo, emailCodes, owners, masterAccounts, config.masterEmailVerification);
  const webauthn = new WebAuthnService(repo, config.webauthn);

  const ctx = new RequestContext(config.webauthn.origins, config.trustProxy);
  const bearer = requireAuth(oauth);
  const clientAdmin = requireRoleOrMaster(oauth, "client_admin", (token) => masterAuth.session(token));

  return {
    oauth,
    bearer,
    registerRoutes(app) {
      registerOAuthRoutes(app, { oauth, idTokens, bearer });
      registerSignInRoutes(app, { signIn, oauth, webauthn, ctx, bearer });
      registerPasswordRoutes(app, { passwords, ctx, bearer });
      registerAccountRoutes(app, { accounts, bearer });
      registerDeviceRoutes(app, { devices, bearer });
      registerPasskeyRoutes(app, { webauthn, bearer });
      registerMasterRoutes(app, { masterAuth, ctx });
      registerClientRoutes(app, { clients, owners, clientAdmin });
    }
  };
}
