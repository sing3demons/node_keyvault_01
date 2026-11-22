// /secrets/*: values in Key Vault, ownership / sharing in the app database.
// Every route needs a user's Bearer token, so `c.get("user")` is the caller.

import { Controller, Delete, Get, Put, UseInterceptors, type Ctx } from "../common/kp/index.js";
import { Bearer } from "../shared/middleware.js";
import type { Actor } from "./acl.js";
import { grantParams, secretNameParam, setGrantBody, setSecretBody, transferBody } from "./schemas.js";
import type { IKeyVaultService } from "./service.js";

@Controller("/secrets")
@UseInterceptors(Bearer)
export class KeyVaultController {
  constructor(private readonly service: IKeyVaultService) {}

  /** GET /secrets — every managed secret's name/metadata, owner and the caller's access. */
  @Get("/")
  async getSecrets(c: Ctx) {
    return c.json({ secrets: await this.service.getSecrets(this.actor(c)) });
  }

  /** GET /secrets/:name — value (needs read) */
  @Get("/:name")
  async getSecret(c: Ctx<"/:name">) {
    const { name } = c.safeParam(secretNameParam);
    const value = await this.service.getSecret(this.actor(c), name);
    return c.json({ name, value });
  }

  /** PUT /secrets/:name  body: { value } — create (caller owns it, 201) or update (needs write, 204) */
  @Put("/:name")
  async setSecret(c: Ctx<"/:name">) {
    const { name } = c.safeParam(secretNameParam);
    const { value } = await c.safeBody(setSecretBody);
    const { created } = await this.service.setSecret(this.actor(c), name, value);
    return created ? c.json({ name }, 201) : c.body(null, 204);
  }

  /** DELETE /secrets/:name (needs delete) */
  @Delete("/:name")
  async deleteSecret(c: Ctx<"/:name">) {
    const { name } = c.safeParam(secretNameParam);
    await this.service.deleteSecret(this.actor(c), name);
    return c.body(null, 204);
  }

  // --- sharing (owner only)

  /** GET /secrets/:name/grants (owner) */
  @Get("/:name/grants")
  async getGrants(c: Ctx<"/:name/grants">) {
    const { name } = c.safeParam(secretNameParam);
    return c.json({ grants: await this.service.getGrants(this.actor(c), name) });
  }

  /** PUT /secrets/:name/grants/:username  body: { permissions } (owner); [] revokes */
  @Put("/:name/grants/:username")
  async setGrant(c: Ctx<"/:name/grants/:username">) {
    const { name, username } = c.safeParam(grantParams);
    const { permissions } = await c.safeBody(setGrantBody);
    return c.json({ grants: await this.service.setGrant(this.actor(c), name, username, permissions) });
  }

  /** DELETE /secrets/:name/grants/:username (owner) */
  @Delete("/:name/grants/:username")
  async deleteGrant(c: Ctx<"/:name/grants/:username">) {
    const { name, username } = c.safeParam(grantParams);
    return c.json({ grants: await this.service.setGrant(this.actor(c), name, username, []) });
  }

  // --- ownership transfer (owner or admin)

  /** PUT /secrets/:name/owner  body: { username } — owner gives it away, or an admin reassigns it */
  @Put("/:name/owner")
  async transferOwnership(c: Ctx<"/:name/owner">) {
    const { name } = c.safeParam(secretNameParam);
    const { username } = await c.safeBody(transferBody);
    return c.json(await this.service.transferOwnership(this.actor(c), name, username));
  }

  private actor(c: Ctx<any>): Actor {
    const user = c.get("user");
    return { id: user.id, isAdmin: user.roles.includes("admin") };
  }
}
