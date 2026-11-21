import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "postgresql",
  schema: ["./src/auth/repositories/drizzle/schema.ts", "./src/keyvault/repositories/drizzle-schema.ts"],
  out: "./drizzle",
  dbCredentials: { url: process.env.DATABASE_URL ?? "postgres://keyvault:keyvault@localhost:5432/keyvault" }
});
