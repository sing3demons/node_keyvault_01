// /secrets/*: values in Key Vault, ownership / sharing in the app database. All behind a user's Bearer token.

import type { Hono, MiddlewareHandler } from "hono";
import type { AuthEnv } from "../shared/middleware.js";
import type { KeyVaultController } from "./controller.js";

export function registerSecretRoutes(
  app: Hono<AuthEnv>,
  { secrets, bearer }: { secrets: KeyVaultController; bearer: MiddlewareHandler<AuthEnv> }
) {
  app.use("/secrets", bearer);
  app.use("/secrets/*", bearer);

  app.get("/secrets", (c) => secrets.getSecrets(c));
  app.get("/secrets/:name", (c) => secrets.getSecret(c));
  app.put("/secrets/:name", (c) => secrets.setSecret(c));
  app.delete("/secrets/:name", (c) => secrets.deleteSecret(c));

  // sharing (owner only)
  app.get("/secrets/:name/grants", (c) => secrets.getGrants(c));
  app.put("/secrets/:name/grants/:username", (c) => secrets.setGrant(c));
  app.delete("/secrets/:name/grants/:username", (c) => secrets.deleteGrant(c));
  // ownership transfer (owner or admin)
  app.put("/secrets/:name/owner", (c) => secrets.transferOwnership(c));
}
