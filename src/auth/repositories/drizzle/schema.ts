import { sql } from "drizzle-orm";
import {
  CLIENT_GRANT_TYPES,
  EMAIL_VERIFICATION_METHODS,
  SIGN_IN_METHODS,
  TOKEN_ENDPOINT_AUTH_METHODS
} from "../../model.js";
import { boolean, check, index, integer, pgTable, primaryKey, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

export const users = pgTable("users", {
  id: uuid("id").primaryKey(),
  username: text("username").notNull().unique(),
  // nullable: accounts created before email was collected (UNIQUE allows many NULLs)
  email: text("email").unique(),
  emailVerifiedAt: ts("email_verified_at"),
  preferredLang: text("preferred_lang"),
  roles: text("roles", { enum: ["admin"] })
    .array()
    .notNull()
    .default(sql`'{}'::text[]`),
  createdAt: ts("created_at").notNull()
});

/** User.profiles[]: one row per language; `position` keeps the list order (profiles[0] is the fallback). */
export const userProfiles = pgTable(
  "user_profiles",
  {
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    lang: text("lang").notNull(),
    firstName: text("first_name").notNull(),
    lastName: text("last_name").notNull(),
    position: integer("position").notNull()
  },
  (t) => [primaryKey({ columns: [t.userId, t.lang] })]
);

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

/** One-time codes sent by email (only sha256 of the code is stored). */
export const emailChallenges = pgTable(
  "email_challenges",
  {
    id: text("id").primaryKey(),
    purpose: text("purpose", { enum: ["signin", "verify"] }).notNull(),
    reason: text("reason", { enum: ["register", "verify_email", "login"] }).notNull(),
    method: text("method", { enum: ["code", "link"] }).notNull().default("code"),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    clientId: text("client_id"),
    codeHash: text("code_hash").notNull(),
    approvedAt: ts("approved_at"),
    attempts: integer("attempts").notNull().default(0),
    sends: integer("sends").notNull().default(1),
    sentAt: ts("sent_at").notNull(),
    authRequestId: text("auth_request_id"),
    expiresAt: ts("expires_at").notNull()
  },
  (t) => [index("email_challenges_expires_at_idx").on(t.expiresAt)]
);

/** Browsers a user signed in from: one row per (user, device cookie). */
export const devices = pgTable(
  "devices",
  {
    id: uuid("id").primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    keyHash: text("key_hash").notNull(),
    name: text("name").notNull(),
    userAgent: text("user_agent").notNull(),
    ip: text("ip"),
    createdAt: ts("created_at").notNull(),
    lastSignInAt: ts("last_sign_in_at").notNull(),
    lastSeenAt: ts("last_seen_at").notNull(),
    lastMethod: text("last_method", { enum: SIGN_IN_METHODS }).notNull(),
    signIns: integer("sign_ins").notNull().default(1)
  },
  (t) => [uniqueIndex("devices_user_key_idx").on(t.userId, t.keyHash), index("devices_user_seen_idx").on(t.userId, t.lastSeenAt)]
);

/** Registered OAuth clients (RFC 7591 metadata + per-client settings). */
export const oauthClients = pgTable("oauth_clients", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  tokenEndpointAuthMethod: text("token_endpoint_auth_method", { enum: TOKEN_ENDPOINT_AUTH_METHODS }).notNull(),
  secretHash: text("secret_hash"),
  redirectUris: text("redirect_uris").array().notNull(),
  grantTypes: text("grant_types", { enum: CLIENT_GRANT_TYPES }).array().notNull(),
  scope: text("scope").notNull(),
  clientUri: text("client_uri"),
  initiateLoginUri: text("initiate_login_uri"),
  accessTokenTtlSec: integer("access_token_ttl_sec").notNull(),
  refreshTokenTtlSec: integer("refresh_token_ttl_sec").notNull(),
  idTokenTtlSec: integer("id_token_ttl_sec").notNull(),
  emailVerification: text("email_verification", { enum: EMAIL_VERIFICATION_METHODS }).notNull(),
  createdAt: ts("created_at").notNull(),
  updatedAt: ts("updated_at").notNull()
});

export const authRequests = pgTable(
  "auth_requests",
  {
    id: text("id").primaryKey(),
    clientId: text("client_id").notNull(),
    redirectUri: text("redirect_uri").notNull(),
    state: text("state"),
    scope: text("scope").notNull(),
    codeChallenge: text("code_challenge").notNull(),
    nonce: text("nonce"),
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
    nonce: text("nonce"),
    authTime: ts("auth_time"),
    deviceId: uuid("device_id"),
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
    deviceId: uuid("device_id"),
    expiresAt: ts("expires_at").notNull()
  },
  (t) => [
    index("access_tokens_family_id_idx").on(t.familyId),
    index("access_tokens_expires_at_idx").on(t.expiresAt),
    index("access_tokens_user_device_idx").on(t.userId, t.deviceId)
  ]
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
    authTime: ts("auth_time"),
    deviceId: uuid("device_id"),
    expiresAt: ts("expires_at").notNull()
  },
  (t) => [
    index("refresh_tokens_family_id_idx").on(t.familyId),
    index("refresh_tokens_expires_at_idx").on(t.expiresAt),
    index("refresh_tokens_user_device_idx").on(t.userId, t.deviceId)
  ]
);
