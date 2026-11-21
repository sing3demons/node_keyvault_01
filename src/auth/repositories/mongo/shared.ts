// Helpers shared by the MongoDB repositories: document <-> domain mapping, ids, duplicate-key errors.

import { ObjectId, type Collection, type Document } from "mongodb";
import { DuplicateKeyError } from "../../repository.js";

/** A domain record stored with its id as `_id`. */
export type Doc<T extends { id: string }> = Omit<T, "id"> & { _id: string };

/** Domain -> document: `id` becomes `_id`, undefined fields are left out. */
export const toDoc = <T extends { id: string }>({ id, ...rest }: T): Doc<T> => {
  const doc: Record<string, unknown> = { _id: id };
  for (const [k, v] of Object.entries(rest)) if (v !== undefined) doc[k] = v;
  return doc as Doc<T>;
};

/** Document -> domain: `_id` becomes `id`, nulls are dropped, ObjectIds become hex strings. */
export const fromDoc = <T extends { id: string }>(doc: Document | null): T | null => {
  if (!doc) return null;
  const { _id, ...rest } = doc;
  const out: Record<string, unknown> = { id: idOf(_id) };
  for (const [k, v] of Object.entries(rest)) if (v !== null) out[k] = v instanceof ObjectId ? v.toHexString() : v;
  return out as T;
};

export const idOf = (id: unknown): string => (id instanceof ObjectId ? id.toHexString() : String(id));

/**
 * Ids are strings (UUID) now; documents written by the earlier Mongo-only version used ObjectId.
 * Match either form so existing users/passkeys keep working.
 */
export const byId = (id: string): string =>
  (/^[0-9a-f]{24}$/i.test(id) ? { $in: [id, new ObjectId(id)] } : id) as unknown as string;

/** E11000 -> DuplicateKeyError naming the colliding field (from the violated index); otherwise null. */
export function duplicateError(error: unknown): DuplicateKeyError | null {
  const e = error as { code?: number; keyPattern?: Record<string, unknown> };
  if (e.code !== 11000) return null;
  const key = Object.keys(e.keyPattern ?? {})[0] ?? "";
  if (key === "username" || key === "email") return new DuplicateKeyError(key);
  if (key.startsWith("credentials")) return new DuplicateKeyError("credential");
  return new DuplicateKeyError("id");
}

/** insertOne of a domain record; a duplicate _id becomes DuplicateKeyError("id"). */
export async function insertDoc<T extends { id: string }>(col: Collection<Doc<T>>, value: T, what: string): Promise<void> {
  try {
    await col.insertOne(toDoc(value) as never);
  } catch (error) {
    if (duplicateError(error)) throw new DuplicateKeyError("id", `${what} already exists`);
    throw error;
  }
}

/** Mongo removes a document once its `expiresAt` has passed (TTL monitor, ~1 min resolution). */
export const TTL = { expireAfterSeconds: 0 } as const;
