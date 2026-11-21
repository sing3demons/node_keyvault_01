CREATE TABLE "secret_acls" (
	"name" text PRIMARY KEY NOT NULL,
	"owner_id" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "secret_grants" (
	"secret_name" text NOT NULL,
	"user_id" text NOT NULL,
	"permissions" text[] NOT NULL,
	CONSTRAINT "secret_grants_secret_name_user_id_pk" PRIMARY KEY("secret_name","user_id")
);
--> statement-breakpoint
ALTER TABLE "secret_grants" ADD CONSTRAINT "secret_grants_secret_name_secret_acls_name_fk" FOREIGN KEY ("secret_name") REFERENCES "public"."secret_acls"("name") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "secret_acls_owner_id_idx" ON "secret_acls" USING btree ("owner_id");