import express from "express";
import path from "node:path";
import { config } from "./config.js";
import { createSecretStore } from "./secret-store.js";

const app = express();
const secretStore = createSecretStore();
const publicDirPath = path.resolve(process.cwd(), "public");

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return "Unknown error";
}

function getErrorStatusCode(error: unknown): number {
  if (typeof error === "object" && error !== null && "statusCode" in error) {
    const statusCode = (error as { statusCode?: unknown }).statusCode;
    if (typeof statusCode === "number") {
      return statusCode;
    }
  }
  return 500;
}

app.use(express.json());
app.use(express.static(publicDirPath));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", provider: config.secretProvider });
});

app.get("/secrets", async (_req, res) => {
  try {
    res.json({ secrets: await secretStore.listSecrets() });
  } catch (error) {
    res.status(getErrorStatusCode(error)).json({ message: getErrorMessage(error) });
  }
});

app.get("/secrets/:name", async (req, res) => {
  try {
    const value = await secretStore.getSecret(req.params.name);
    res.json({ name: req.params.name, value });
  } catch (error) {
    const statusCode = getErrorStatusCode(error);
    res.status(statusCode).json({ message: getErrorMessage(error) });
  }
});

app.put("/secrets/:name", async (req, res) => {
  const value = req.body?.value;
  if (typeof value !== "string" || value.length === 0) {
    res.status(400).json({ message: "Body must include a non-empty string field: value" });
    return;
  }

  try {
    await secretStore.setSecret(req.params.name, value);
    res.status(204).send();
  } catch (error) {
    const statusCode = getErrorStatusCode(error);
    res.status(statusCode).json({ message: getErrorMessage(error) });
  }
});

app.delete("/secrets/:name", async (req, res) => {
  try {
    await secretStore.deleteSecret(req.params.name);
    res.status(204).send();
  } catch (error) {
    const statusCode = getErrorStatusCode(error);
    res.status(statusCode).json({ message: getErrorMessage(error) });
  }
});

app.listen(config.port, () => {
  console.log(`Server is running on port ${config.port} with provider=${config.secretProvider}`);
});
