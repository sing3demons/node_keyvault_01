// /admin/clients (RFC 7591 metadata, RFC 7592-style read / update / delete) and /admin/client-owners.
// Callers: a client_admin user's Bearer token, or a master session (until the master is disabled).

import { Controller, Delete, Get, Post, Put, UseInterceptors, type Ctx } from "../../common/kp/index.js";
import { ClientAdmin } from "../../shared/middleware.js";
import { clientIdParam, clientMetadataBody, usernameParam } from "../schemas.js";
import type { ClientService } from "./clients.js";
import type { Actor, ClientOwnerService } from "./owners.js";

@Controller("/admin/clients")
@UseInterceptors(ClientAdmin)
export class ClientController {
  constructor(private readonly clients: ClientService) {}

  @Get("/")
  async list(c: Ctx) {
    return c.json({ clients: await this.clients.list(), default_mail_from: this.clients.defaultMailFrom });
  }

  @Get("/:id")
  async get(c: Ctx) {
    return c.json(await this.clients.get(c.safeParam(clientIdParam).id));
  }

  /** RFC 7591 §3.1; the response carries client_secret once (confidential clients). */
  @Post("/")
  async register(c: Ctx) {
    c.header("Cache-Control", "no-store");
    return c.json(await this.clients.register(await c.safeBody(clientMetadataBody)), 201);
  }

  /** RFC 7592 §2.2: complete metadata (omitted optional fields are cleared). */
  @Put("/:id")
  async update(c: Ctx) {
    c.header("Cache-Control", "no-store");
    const { id } = c.safeParam(clientIdParam);
    return c.json(await this.clients.update(id, await c.safeBody(clientMetadataBody)));
  }

  /** New client_secret (the old one stops working). */
  @Post("/:id/secret")
  async rotateSecret(c: Ctx) {
    c.header("Cache-Control", "no-store");
    return c.json(await this.clients.rotateSecret(c.safeParam(clientIdParam).id));
  }

  /** Also revokes its tokens (RFC 7592 §2.3). */
  @Delete("/:id")
  async remove(c: Ctx) {
    // the master is not signed in through any client, so there is nothing to protect
    const callerClientId = c.get("master") ? undefined : c.get("user").clientId;
    await this.clients.delete(c.safeParam(clientIdParam).id, callerClientId);
    return c.body(null, 204);
  }
}

/** Owners (role client_admin) and the master credential. */
@Controller("/admin/client-owners")
@UseInterceptors(ClientAdmin)
export class ClientOwnerController {
  constructor(private readonly owners: ClientOwnerService) {}

  /** -> { owners, master: { configured, enabled, ... }, you } */
  @Get("/")
  async view(c: Ctx) {
    return c.json({ ...(await this.owners.view()), you: actor(c) });
  }

  /** Needs another owner; MASTER_CREDENTIALS stops working. */
  @Post("/master/disable")
  async disableMaster(c: Ctx) {
    return c.json(await this.owners.disableMaster(actor(c)));
  }

  /** Owners only. */
  @Post("/master/enable")
  async enableMaster(c: Ctx) {
    return c.json(await this.owners.enableMaster(actor(c)));
  }

  /** Give the client_admin role. */
  @Put("/:username")
  async add(c: Ctx) {
    return c.json(await this.owners.addOwner(c.safeParam(usernameParam).username));
  }

  /** Never the last one while the master is disabled. */
  @Delete("/:username")
  async remove(c: Ctx) {
    return c.json(await this.owners.removeOwner(c.safeParam(usernameParam).username));
  }
}

function actor(c: Ctx): Actor {
  const master = c.get("master");
  if (master) return { kind: "master", name: master.username };
  const user = c.get("user");
  return { kind: "user", id: user.id, username: user.username };
}
