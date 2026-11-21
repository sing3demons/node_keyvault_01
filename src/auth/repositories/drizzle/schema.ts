import { boolean, index, integer, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

export const users = pgTable("users", {
  id: uuid("id").primaryKey(),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  createdAt: ts("created_at").notNull()
});

export const webauthnCredentials = pgTable(
  "webauthn_credentials",
  {
    id: uuid("id").primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    credId: text("cred_id").notNull().unique(),
    publicKeyPem: text("public_key_pem").notNull(),
    counter: integer("counter").notNull().default(0),
    transports: text("transports").array(),
    name: text("name").notNull(),
    createdAt: ts("created_at").notNull(),
    lastUsedAt: ts("last_used_at")
  },
  (t) => [index("webauthn_credentials_user_id_idx").on(t.userId)]
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
