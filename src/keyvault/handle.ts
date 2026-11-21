import type { Context } from 'hono'
import { IKeyVaultService } from './service';


export class KeyVaultHandler {
    constructor(private readonly service: IKeyVaultService) {
    }

    // app.get("/secrets", async (c) => c.json({ secrets: await secretStore.listSecrets() }));
    async getSecrets(ctx: Context) {
        const secrets = await this.service.getSecrets();
        return ctx.json({ secrets });
    }
    async getSecret(ctx: Context) {
        const name = ctx.req.param("name");
        if (!name) {
            return ctx.json({ message: "Name parameter is required" }, 400);
        }
        const value = await this.service.getSecret(name);
        return ctx.json({ name, value });
    }
    async setSecret(ctx: Context) {
        const name = ctx.req.param("name");
        if (!name) {
            return ctx.json({ message: "Name parameter is required" }, 400);
        }
        const body = await ctx.req.json().catch(() => null);
        const value = (body as { value?: unknown } | null)?.value;
        if (typeof value !== "string" || value.length === 0) {
            return ctx.json({ message: "Body must include a non-empty string field: value" }, 400);
        }
        await this.service.setSecret(name, value);
        return ctx.body(null, 204);
    }

    async deleteSecret(ctx: Context) {
        const name = ctx.req.param("name");
        if (!name) {
            return ctx.json({ message: "Name parameter is required" }, 400);
        }
        await this.service.deleteSecret(name);
        return ctx.body(null, 204);
    }
}