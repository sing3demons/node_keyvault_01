// /admin/clients (RFC 7591 metadata, RFC 7592-style read / update / delete) and /admin/client-owners.
// Callers: a client_admin user's Bearer token, or a master session (until the master is disabled).

import type { Context, Hono, MiddlewareHandler } from "hono";
import { parse, parseJsonBody } from "../../shared/http.js";
import type { AuthEnv } from "../../shared/middleware.js";
import { clientIdParam, clientMetadataBody, usernameParam } from "../schemas.js";
import type { ClientService } from "./clients.js";
import type { Actor, ClientOwnerService } from "./owners.js";

export function registerClientRoutes(
  app: Hono<AuthEnv>,
  { clients, owners, clientAdmin }: { clients: ClientService; owners: ClientOwnerService; clientAdmin: MiddlewareHandler<AuthEnv> }
) {
  for (const p of ["/admin/clients", "/admin/clients/*", "/admin/client-owners", "/admin/client-owners/*"]) app.use(p, clientAdmin);

  // --- clients
  app.get("/admin/clients", async (c) => c.json({ clients: await clients.list(), default_mail_from: clients.defaultMailFrom }));

  app.get("/admin/clients/:id", async (c) => c.json(await clients.get(parse(clientIdParam, c.req.param()).id)));

  /** RFC 7591 §3.1; the response carries client_secret once (confidential clients). */
  app.post("/admin/clients", async (c) => {
    c.header("Cache-Control", "no-store");
    return c.json(await clients.register(await parseJsonBody(c, clientMetadataBody)), 201);
  });

  /** RFC 7592 §2.2: complete metadata (omitted optional fields are cleared). */
  app.put("/admin/clients/:id", async (c) => {
    c.header("Cache-Control", "no-store");
    const { id } = parse(clientIdParam, c.req.param());
    return c.json(await clients.update(id, await parseJsonBody(c, clientMetadataBody)));
  });

  /** New client_secret (the old one stops working). */
  app.post("/admin/clients/:id/secret", async (c) => {
    c.header("Cache-Control", "no-store");
    return c.json(await clients.rotateSecret(parse(clientIdParam, c.req.param()).id));
  });

  /** Also revokes its tokens (RFC 7592 §2.3). */
  app.delete("/admin/clients/:id", async (c) => {
    // the master is not signed in through any client, so there is nothing to protect
    const callerClientId = c.get("master") ? undefined : c.get("user").clientId;
    await clients.delete(parse(clientIdParam, c.req.param()).id, callerClientId);
    return c.body(null, 204);
  });

  // --- owners (role client_admin) and the master credential
  /** -> { owners, master: { configured, enabled, ... }, you } */
  app.get("/admin/client-owners", async (c) => c.json({ ...(await owners.view()), you: actor(c) }));

  /** Needs another owner; MASTER_CREDENTIALS stops working. */
  app.post("/admin/client-owners/master/disable", async (c) => c.json(await owners.disableMaster(actor(c))));

  /** Owners only. */
  app.post("/admin/client-owners/master/enable", async (c) => c.json(await owners.enableMaster(actor(c))));

  /** Give the client_admin role. */
  app.put("/admin/client-owners/:username", async (c) => c.json(await owners.addOwner(parse(usernameParam, c.req.param()).username)));

  /** Never the last one while the master is disabled. */
  app.delete("/admin/client-owners/:username", async (c) =>
    c.json(await owners.removeOwner(parse(usernameParam, c.req.param()).username))
  );
}

function actor(c: Context<AuthEnv>): Actor {
  const master = c.get("master");
  if (master) return { kind: "master", name: master.username };
  const user = c.get("user");
  return { kind: "user", id: user.id, username: user.username };
}
