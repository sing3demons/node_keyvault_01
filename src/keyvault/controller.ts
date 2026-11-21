import type { Context } from "hono";
import { parse, parseJsonBody } from "../shared/http.js";
import type { AuthEnv } from "../shared/middleware.js";
import type { Actor } from "./acl.js";
import { grantParams, secretNameParam, setGrantBody, setSecretBody, transferBody } from "./schemas.js";
import type { IKeyVaultService } from "./service.js";

/** All routes sit behind requireAuth, so `c.get("user")` is the caller. */
export class KeyVaultController {
  constructor(private readonly service: IKeyVaultService) {}

  /** PUT /secrets/:name/owner  body: { username } — owner gives it away, or an admin reassigns it */
  async transferOwnership(ctx: Context<AuthEnv>) {
    const { name } = parse(secretNameParam, ctx.req.param());
    const { username } = await parseJsonBody(ctx, transferBody);
    return ctx.json(await this.service.transferOwnership(this.actor(ctx), name, username));
  }

  /** GET /secrets — every managed secret's name/metadata, owner and the caller's access. */
  async getSecrets(ctx: Context<AuthEnv>) {
    return ctx.json({ secrets: await this.service.getSecrets(this.actor(ctx)) });
  }

  /** GET /secrets/:name — value (needs read) */
  async getSecret(ctx: Context<AuthEnv>) {
    const { name } = parse(secretNameParam, ctx.req.param());
    const value = await this.service.getSecret(this.actor(ctx), name);
    return ctx.json({ name, value });
  }

  /** PUT /secrets/:name  body: { value } — create (caller owns it, 201) or update (needs write, 204) */
  async setSecret(ctx: Context<AuthEnv>) {
    const { name } = parse(secretNameParam, ctx.req.param());
    const { value } = await parseJsonBody(ctx, setSecretBody);
    const { created } = await this.service.setSecret(this.actor(ctx), name, value);
    return created ? ctx.json({ name }, 201) : ctx.body(null, 204);
  }

  /** DELETE /secrets/:name (needs delete) */
  async deleteSecret(ctx: Context<AuthEnv>) {
    const { name } = parse(secretNameParam, ctx.req.param());
    await this.service.deleteSecret(this.actor(ctx), name);
    return ctx.body(null, 204);
  }

  /** GET /secrets/:name/grants (owner) */
  async getGrants(ctx: Context<AuthEnv>) {
    const { name } = parse(secretNameParam, ctx.req.param());
    return ctx.json({ grants: await this.service.getGrants(this.actor(ctx), name) });
  }

  /** PUT /secrets/:name/grants/:username  body: { permissions } (owner); [] revokes */
  async setGrant(ctx: Context<AuthEnv>) {
    const { name, username } = parse(grantParams, ctx.req.param());
    const { permissions } = await parseJsonBody(ctx, setGrantBody);
    return ctx.json({ grants: await this.service.setGrant(this.actor(ctx), name, username, permissions) });
  }

  /** DELETE /secrets/:name/grants/:username (owner) */
  async deleteGrant(ctx: Context<AuthEnv>) {
    const { name, username } = parse(grantParams, ctx.req.param());
    return ctx.json({ grants: await this.service.setGrant(this.actor(ctx), name, username, []) });
  }

  private actor(ctx: Context<AuthEnv>): Actor {
    const user = ctx.get("user");
    return { id: user.id, isAdmin: user.roles.includes("admin") };
  }
}
