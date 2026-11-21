import { sql } from "drizzle-orm";
import { boolean, check, index, integer, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

export const users = pgTable("users", {
  id: uuid("id").primaryKey(),
  username: text("username").notNull().unique(),
  createdAt: ts("created_at").notNull()
});

/**
 * One row per credential (User.credentials[]). Columns are grouped by type;
 * CHECK constraints make sure each type carries its required fields.
 */
export const userCredentials = pgTable(
  "user_credentials",
  {
    id: uuid("id").primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    type: text("type", { enum: ["password", "webauthn"] }).notNull(),
    // secret types (password, later pin, ...): hash + algorithm
    value: text("value"),
    algorithm: text("algorithm", { enum: ["argon2id", "bcrypt"] }),
    // type = webauthn
    credId: text("webauthn_cred_id").unique(),
    publicKeyPem: text("webauthn_public_key_pem"),
    counter: integer("webauthn_counter"),
    transports: text("webauthn_transports").array(),
    name: text("webauthn_name"),

    createdAt: ts("created_at").notNull(),
    lastUsedAt: ts("last_used_at")
  },
  (t) => [
    index("user_credentials_user_id_idx").on(t.userId),
    // at most one password per user (add a similar index when adding another secret type)
    uniqueIndex("user_credentials_one_password_idx").on(t.userId).where(sql`${t.type} = 'password'`),
    check(
      "user_credentials_shape",
      sql`(${t.type} = 'password' AND ${t.value} IS NOT NULL AND ${t.algorithm} IS NOT NULL)
       OR (${t.type} = 'webauthn' AND ${t.credId} IS NOT NULL AND ${t.publicKeyPem} IS NOT NULL
           AND ${t.counter} IS NOT NULL AND ${t.name} IS NOT NULL)`
    )
  ]
);

export const webauthnChallenges = pgTable(
  "webauthn_challenges",
  {
    id: text("id").primaryKey(),
    type: text("type", { enum: ["register", "login"] }).notNull(),
    challenge: text("challenge").notNull(),
    userId: uuid("user_id").references(() => users.id, { onDelete: "cascade" }),
    authRequestId: text("auth_request_id"),
    expiresAt: ts("expires_at").notNull()
  },
  (t) => [index("webauthn_challenges_expires_at_idx").on(t.expiresAt)]
);

export const authRequests = pgTable(
  "auth_requests",
  {
    id: text("id").primaryKey(),
    clientId: text("client_id").notNull(),
    redirectUri: text("redirect_uri").notNull(),
    state: text("state"),
    scope: text("scope").notNull(),
    codeChallenge: text("code_challenge").notNull(),
    expiresAt: ts("expires_at").notNull()
  },
  (t) => [index("auth_requests_expires_at_idx").on(t.expiresAt)]
);

export const authCodes = pgTable(
  "auth_codes",
  {
    id: text("id").primaryKey(), // sha256(code)
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    clientId: text("client_id").notNull(),
    redirectUri: text("redirect_uri").notNull(),
    scope: text("scope").notNull(),
    codeChallenge: text("code_challenge").notNull(),
    familyId: text("family_id").notNull(),
    used: boolean("used").notNull().default(false),
    expiresAt: ts("expires_at").notNull()
  },
  (t) => [index("auth_codes_expires_at_idx").on(t.expiresAt)]
);

export const accessTokens = pgTable(
  "access_tokens",
  {
    id: text("id").primaryKey(), // sha256(token)
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    clientId: text("client_id").notNull(),
    scope: text("scope").notNull(),
    familyId: text("family_id").notNull(),
    expiresAt: ts("expires_at").notNull()
  },
  (t) => [index("access_tokens_family_id_idx").on(t.familyId), index("access_tokens_expires_at_idx").on(t.expiresAt)]
);

export const refreshTokens = pgTable(
  "refresh_tokens",
  {
    id: text("id").primaryKey(), // sha256(token)
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    clientId: text("client_id").notNull(),
    scope: text("scope").notNull(),
    familyId: text("family_id").notNull(),
    revoked: boolean("revoked").notNull().default(false),
    expiresAt: ts("expires_at").notNull()
  },
  (t) => [index("refresh_tokens_family_id_idx").on(t.familyId), index("refresh_tokens_expires_at_idx").on(t.expiresAt)]
);
