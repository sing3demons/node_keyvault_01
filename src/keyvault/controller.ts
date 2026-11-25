import type { Context } from 'hono'
import { IKeyVaultService } from './service';


export class KeyVaultController {
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
        const body = (await ctx.req.json().catch(() => null)) as { value?: unknown; expiresOn?: unknown } | null;
        const value = body?.value;
        if (typeof value !== "string" || value.length === 0) {
            return ctx.json({ message: "Body must include a non-empty string field: value" }, 400);
        }
        // expiresOn: optional ISO date string; null/absent = no expiry
        const rawExpiresOn = body?.expiresOn;
        let expiresOn: Date | undefined;
        if (rawExpiresOn !== undefined && rawExpiresOn !== null) {
            expiresOn = typeof rawExpiresOn === "string" ? new Date(rawExpiresOn) : undefined;
            if (!expiresOn || Number.isNaN(expiresOn.getTime())) {
                return ctx.json({ message: "expiresOn must be an ISO date string or null" }, 400);
            }
        }
        await this.service.setSecret(name, value, { expiresOn });
        return ctx.body(null, 204);
    }

    // POST /keypairs/:name  body (optional): { modulusLength?: 2048|3072|4096, validDays?: number }
    async generateKeyPair(ctx: Context) {
        const name = ctx.req.param("name");
        // "-private"/"-public" are appended, so keep the base name within Key Vault's 127-char limit
        if (!name || !/^[0-9A-Za-z-]{1,119}$/.test(name)) {
            return ctx.json({ message: "Name must be 1-119 letters, numbers or dashes" }, 400);
        }
        const body = ((await ctx.req.json().catch(() => null)) ?? {}) as { modulusLength?: unknown; validDays?: unknown };

        const modulusLength = body.modulusLength ?? 2048;
        if (modulusLength !== 2048 && modulusLength !== 3072 && modulusLength !== 4096) {
            return ctx.json({ message: "modulusLength must be 2048, 3072 or 4096" }, 400);
        }
        const validDays = body.validDays ?? 365;
        if (typeof validDays !== "number" || !Number.isInteger(validDays) || validDays < 1 || validDays > 3650) {
            return ctx.json({ message: "validDays must be an integer between 1 and 3650" }, 400);
        }

        const result = await this.service.generateKeyPair(name, { modulusLength, validDays });
        return ctx.json(result, 201);
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