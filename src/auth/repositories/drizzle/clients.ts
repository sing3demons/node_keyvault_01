// Registered OAuth clients.

import { asc, eq } from "drizzle-orm";
import type { OAuthClient } from "../../model.js";
import type { ClientRepository } from "../../repository.js";
import { oauthClients } from "./schema.js";
import { clean, write, type Db } from "./shared.js";

export class DrizzleClientRepository implements ClientRepository {
  constructor(private readonly db: Db) {}

  create(c: OAuthClient): Promise<void> {
    return write("Client", () => this.db.insert(oauthClients).values(c));
  }

  async findById(id: string): Promise<OAuthClient | null> {
    return clean<OAuthClient>((await this.db.select().from(oauthClients).where(eq(oauthClients.id, id)))[0]);
  }

  async list(): Promise<OAuthClient[]> {
    return (await this.db.select().from(oauthClients).orderBy(asc(oauthClients.createdAt))).map((r) => clean<OAuthClient>(r)!);
  }

  async update(c: OAuthClient): Promise<boolean> {
    const { id, createdAt: _createdAt, ...rest } = c;
    const rows = await this.db
      .update(oauthClients)
      // optional fields the client no longer has are cleared
      .set({
        ...rest,
        secretHash: c.secretHash ?? null,
        clientUri: c.clientUri ?? null,
        initiateLoginUri: c.initiateLoginUri ?? null,
        mailFrom: c.mailFrom ?? null
      })
      .where(eq(oauthClients.id, id))
      .returning({ id: oauthClients.id });
    return rows.length > 0;
  }

  async delete(id: string): Promise<boolean> {
    return (await this.db.delete(oauthClients).where(eq(oauthClients.id, id)).returning({ id: oauthClients.id })).length > 0;
  }
}
