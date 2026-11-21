CREATE TABLE "user_profiles" (
	"user_id" uuid NOT NULL,
	"lang" text NOT NULL,
	"first_name" text NOT NULL,
	"last_name" text NOT NULL,
	"position" integer NOT NULL,
	CONSTRAINT "user_profiles_user_id_lang_pk" PRIMARY KEY("user_id","lang")
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "email" text;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "preferred_lang" text;--> statement-breakpoint
ALTER TABLE "user_profiles" ADD CONSTRAINT "user_profiles_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_email_unique" UNIQUE("email");