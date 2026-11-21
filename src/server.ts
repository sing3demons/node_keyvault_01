import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { config } from "./config.js";
import { createSecretStore } from "./secret-store.js";

const secretStore = createSecretStore();

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown error";
}

function getErrorStatusCode(error: unknown): ContentfulStatusCode {
  if (typeof error === "object" && error !== null && "statusCode" in error) {
    const statusCode = (error as { statusCode?: unknown }).statusCode;
    if (typeof statusCode === "number" && statusCode >= 400 && statusCode < 600) {
      return statusCode as ContentfulStatusCode;
    }
  }
  return 500;
}

const app = new Hono();

app.onError((error, c) => c.json({ message: getErrorMessage(error) }, getErrorStatusCode(error)));

app.get("/health", (c) => c.json({ status: "ok", provider: config.secretProvider }));

app.get("/secrets", async (c) => c.json({ secrets: await secretStore.listSecrets() }));

app.get("/secrets/:name", async (c) => {
  const name = c.req.param("name");
  return c.json({ name, value: await secretStore.getSecret(name) });
});

app.put("/secrets/:name", async (c) => {
  const body = await c.req.json().catch(() => null);
  const value = (body as { value?: unknown } | null)?.value;
  if (typeof value !== "string" || value.length === 0) {
    return c.json({ message: "Body must include a non-empty string field: value" }, 400);
  }
  await secretStore.setSecret(c.req.param("name"), value);
  return c.body(null, 204);
});

app.delete("/secrets/:name", async (c) => {
  await secretStore.deleteSecret(c.req.param("name"));
  return c.body(null, 204);
});

// React UI (built by `vite build` into dist/public)
app.use("/*", serveStatic({ root: "./dist/public" }));

serve({ fetch: app.fetch, port: config.port }, (info) => {
  console.log(`Server is running on port ${info.port} with provider=${config.secretProvider}`);
});
