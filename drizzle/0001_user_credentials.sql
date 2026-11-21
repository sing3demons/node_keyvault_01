CREATE TABLE "user_credentials" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"type" text NOT NULL,
	"value" text,
	"algorithm" text,
	"webauthn_cred_id" text,
	"webauthn_public_key_pem" text,
	"webauthn_counter" integer,
	"webauthn_transports" text[],
	"webauthn_name" text,
	"created_at" timestamp with time zone NOT NULL,
	"last_used_at" timestamp with time zone,
	CONSTRAINT "user_credentials_webauthn_cred_id_unique" UNIQUE("webauthn_cred_id"),
	CONSTRAINT "user_credentials_shape" CHECK (("user_credentials"."type" = 'password' AND "user_credentials"."value" IS NOT NULL AND "user_credentials"."algorithm" IS NOT NULL)
       OR ("user_credentials"."type" = 'webauthn' AND "user_credentials"."webauthn_cred_id" IS NOT NULL AND "user_credentials"."webauthn_public_key_pem" IS NOT NULL
           AND "user_credentials"."webauthn_counter" IS NOT NULL AND "user_credentials"."webauthn_name" IS NOT NULL))
);
--> statement-breakpoint
ALTER TABLE "user_credentials" ADD CONSTRAINT "user_credentials_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "user_credentials_user_id_idx" ON "user_credentials" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "user_credentials_one_password_idx" ON "user_credentials" USING btree ("user_id") WHERE "user_credentials"."type" = 'password';--> statement-breakpoint
-- data migration (hand-written): users.password_hash + webauthn_credentials -> user_credentials
INSERT INTO "user_credentials" ("id", "user_id", "type", "value", "algorithm", "created_at")
SELECT gen_random_uuid(), "id", 'password', "password_hash",
       CASE WHEN "password_hash" LIKE '$argon2%' THEN 'argon2id' ELSE 'bcrypt' END, "created_at"
FROM "users" WHERE "password_hash" IS NOT NULL;--> statement-breakpoint
INSERT INTO "user_credentials" ("id", "user_id", "type", "webauthn_cred_id", "webauthn_public_key_pem",
                                "webauthn_counter", "webauthn_transports", "webauthn_name", "created_at", "last_used_at")
SELECT "id", "user_id", 'webauthn', "cred_id", "public_key_pem", "counter", "transports", "name", "created_at", "last_used_at"
FROM "webauthn_credentials";--> statement-breakpoint
ALTER TABLE "users" DROP COLUMN "password_hash";