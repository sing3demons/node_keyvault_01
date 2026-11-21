CREATE TABLE "oauth_clients" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"token_endpoint_auth_method" text NOT NULL,
	"secret_hash" text,
	"redirect_uris" text[] NOT NULL,
	"grant_types" text[] NOT NULL,
	"scope" text NOT NULL,
	"client_uri" text,
	"initiate_login_uri" text,
	"access_token_ttl_sec" integer NOT NULL,
	"refresh_token_ttl_sec" integer NOT NULL,
	"id_token_ttl_sec" integer NOT NULL,
	"email_verification" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "email_challenges" ADD COLUMN "client_id" text;