import { index, pgTable, primaryKey, text, timestamp } from "drizzle-orm/pg-core";

/** One row per owned secret; `name` is the lowercased Key Vault secret name. */
export const secretAcls = pgTable(
  "secret_acls",
  {
    name: text("name").primaryKey(),
    // text, not a FK: keyvault does not depend on the auth schema
    ownerId: text("owner_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" }).notNull()
  },
  (t) => [index("secret_acls_owner_id_idx").on(t.ownerId)]
);

/** Permissions the owner granted to other users. */
export const secretGrants = pgTable(
  "secret_grants",
  {
    secretName: text("secret_name")
      .notNull()
      .references(() => secretAcls.name, { onDelete: "cascade" }),
    userId: text("user_id").notNull(),
    permissions: text("permissions", { enum: ["read", "write", "delete"] })
      .array()
      .notNull()
  },
  (t) => [primaryKey({ columns: [t.secretName, t.userId] })]
);
