import type { Context } from "hono";
import { parse, parseJsonBody } from "../shared/http.js";
import { secretNameParam, setSecretBody } from "./schemas.js";
import type { IKeyVaultService } from "./service.js";

export class KeyVaultController {
  constructor(private readonly service: IKeyVaultService) {}

  /** GET /secrets */
  async getSecrets(ctx: Context) {
    const secrets = await this.service.getSecrets();
    return ctx.json({ secrets });
  }

  /** GET /secrets/:name */
  async getSecret(ctx: Context) {
    const { name } = parse(secretNameParam, ctx.req.param());
    const value = await this.service.getSecret(name);
    return ctx.json({ name, value });
  }

  /** PUT /secrets/:name  body: { value } */
  async setSecret(ctx: Context) {
    const { name } = parse(secretNameParam, ctx.req.param());
    const { value } = await parseJsonBody(ctx, setSecretBody);
    await this.service.setSecret(name, value);
    return ctx.body(null, 204);
  }

  /** DELETE /secrets/:name */
  async deleteSecret(ctx: Context) {
    const { name } = parse(secretNameParam, ctx.req.param());
    await this.service.deleteSecret(name);
    return ctx.body(null, 204);
  }
}
