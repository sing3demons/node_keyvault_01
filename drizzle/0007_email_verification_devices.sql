CREATE TABLE "devices" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"key_hash" text NOT NULL,
	"name" text NOT NULL,
	"user_agent" text NOT NULL,
	"ip" text,
	"created_at" timestamp with time zone NOT NULL,
	"last_sign_in_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"last_method" text NOT NULL,
	"sign_ins" integer DEFAULT 1 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "email_challenges" (
	"id" text PRIMARY KEY NOT NULL,
	"purpose" text NOT NULL,
	"reason" text NOT NULL,
	"method" text DEFAULT 'code' NOT NULL,
	"user_id" uuid NOT NULL,
	"email" text NOT NULL,
	"code_hash" text NOT NULL,
	"approved_at" timestamp with time zone,
	"attempts" integer DEFAULT 0 NOT NULL,
	"sends" integer DEFAULT 1 NOT NULL,
	"sent_at" timestamp with time zone NOT NULL,
	"auth_request_id" text,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "access_tokens" ADD COLUMN "device_id" uuid;--> statement-breakpoint
ALTER TABLE "auth_codes" ADD COLUMN "device_id" uuid;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "device_id" uuid;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "email_verified_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "devices" ADD CONSTRAINT "devices_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_challenges" ADD CONSTRAINT "email_challenges_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "devices_user_key_idx" ON "devices" USING btree ("user_id","key_hash");--> statement-breakpoint
CREATE INDEX "devices_user_seen_idx" ON "devices" USING btree ("user_id","last_seen_at");--> statement-breakpoint
CREATE INDEX "email_challenges_expires_at_idx" ON "email_challenges" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "access_tokens_user_device_idx" ON "access_tokens" USING btree ("user_id","device_id");--> statement-breakpoint
CREATE INDEX "refresh_tokens_user_device_idx" ON "refresh_tokens" USING btree ("user_id","device_id");