// Helpers shared by the PostgreSQL (Drizzle) repositories.

import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import { DuplicateKeyError } from "../../repository.js";
import type * as schema from "./schema.js";

export type Db = NodePgDatabase<typeof schema>;
/** A transaction handle (same query API as Db). */
export type Tx = Parameters<Parameters<Db["transaction"]>[0]>[0];

/** SQL NULL -> undefined so rows match the domain types. */
export const clean = <T>(row: Record<string, unknown> | undefined): T | null => {
  if (!row) return null;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) if (v !== null) out[k] = v;
  return out as T;
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** uuid columns reject other formats, so callers check before querying. */
export const isUuid = (id: string): boolean => UUID_RE.test(id);

/**
 * Runs a write, mapping Postgres unique_violation (possibly wrapped by DrizzleQueryError) to DuplicateKeyError,
 * naming the field from the violated constraint.
 */
export async function write(what: string, run: () => Promise<unknown>): Promise<void> {
  try {
    await run();
  } catch (error) {
    const e = error as { code?: string; constraint?: string; cause?: { code?: string; constraint?: string } };
    const pg = e.cause?.code ? e.cause : e;
    if (pg.code !== "23505") throw error;
    const constraint = pg.constraint ?? "";
    if (constraint.includes("email")) throw new DuplicateKeyError("email");
    if (constraint.includes("username")) throw new DuplicateKeyError("username");
    if (constraint.startsWith("user_credentials")) throw new DuplicateKeyError("credential");
    throw new DuplicateKeyError("id", `${what} already exists`);
  }
}
