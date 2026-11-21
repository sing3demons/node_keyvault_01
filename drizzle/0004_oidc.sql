ALTER TABLE "auth_codes" ADD COLUMN "nonce" text;--> statement-breakpoint
ALTER TABLE "auth_codes" ADD COLUMN "auth_time" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "auth_requests" ADD COLUMN "nonce" text;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "auth_time" timestamp with time zone;