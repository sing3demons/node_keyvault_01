// End-to-end tests against a real server, on MongoDB and PostgreSQL.
//
//   docker compose up -d mongo postgres keyvault mailpit
//   pnpm test:e2e                      # every suite on both databases
//   pnpm test:e2e --db postgres        # one database
//   pnpm test:e2e --only clients,master
//
// Each suite gets a fresh test database (keyvault_e2e — never your dev data) and its own server on
// E2E_PORT (3999). Emails are read from Mailpit (http://localhost:8025). Secrets the tests create in the
// Key Vault emulator, and the test signing-key secret, are removed at the end.

import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";
import pg from "pg";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");
const dev = dotenv.config({ path: join(repo, ".env"), quiet: true }).parsed ?? {};

const PORT = process.env.E2E_PORT ?? "3999";
const DB = "keyvault_e2e";
const MASTER = Buffer.from("master:correct-horse-battery-staple|master@example.com:argon2id").toString("base64");
const KEYS_SECRET = "oidc-signing-keys-e2e";

const mongoUrl = dev.MONGO_URL ?? "mongodb://localhost:27017";
const pgUrl = new URL(dev.DATABASE_URL ?? "postgres://keyvault:keyvault@localhost:5432/keyvault");
const pgAdminUrl = pgUrl.toString();
pgUrl.pathname = `/${DB}`;

/** Everything the server reads, fixed here so the developer's .env cannot change test behaviour. */
const baseEnv = {
  PORT,
  MONGO_DB: DB,
  DATABASE_URL: pgUrl.toString(),
  SMTP_URL: "smtp://localhost:1025",
  MAIL_FROM: "Key Vault Test <no-reply@kv.test>",
  WEBAUTHN_ORIGINS: "http://localhost:5173,http://localhost:3001",
  OAUTH_REDIRECT_URIS: "http://localhost:3001/callback",
  ADMIN_USERNAMES: "admin_e2e",
  OIDC_RETIRED_KEY_GRACE_SEC: "3600",
  OIDC_KEYS_SECRET: KEYS_SECRET,
  EMAIL_VERIFICATION: "code",
  EMAIL_CODE_TTL: "600",
  EMAIL_CODE_MAX_ATTEMPTS: "5",
  EMAIL_CODE_RESEND_COOLDOWN: "30",
  EMAIL_CODE_MAX_SENDS: "5",
  MASTER_CREDENTIALS: MASTER,
  MASTER_EMAIL_VERIFICATION: "otp",
  TRUST_PROXY: "false"
};

/** suite file -> extra server env (and env for the suite itself). */
const SUITES = {
  "email-code": {},
  "email-link": { EMAIL_VERIFICATION: "link", EMAIL_CODE_RESEND_COOLDOWN: "0" },
  clients: {},
  "client-credentials": {},
  master: {},
  "master-link": { file: "master", MASTER_EMAIL_VERIFICATION: "link", MODE: "link" },
  owners: {},
  secrets: {},
  "mail-from": {},
  passkeys: {},
  "password-reset": {},
  "password-reset-link": { file: "password-reset", EMAIL_VERIFICATION: "link", MODE: "link" }
};

// ------------------------------------------------------------------ args
const arg = (name) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
};
const dbs = (arg("db") ?? "mongo,postgres").split(",");
const only = arg("only")?.split(",");
const suites = Object.entries(SUITES).filter(([name]) => !only || only.includes(name));
for (const f of readdirSync(here).filter((f) => f.endsWith(".test.mjs"))) {
  const name = f.replace(".test.mjs", "");
  if (!Object.values(SUITES).some((s) => (s.file ?? "") === name) && !(name in SUITES)) console.warn(`(not in SUITES: ${f})`);
}

// ------------------------------------------------------------------ helpers
/** Drops the test database (and, unless `recreate` is false, creates it empty again). */
async function resetDatabase(db, recreate = true) {
  if (db === "mongo") {
    const client = await MongoClient.connect(mongoUrl);
    await client.db(DB).dropDatabase();
    await client.close();
  } else {
    const client = new pg.Client({ connectionString: pgAdminUrl });
    await client.connect();
    await client.query(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`);
    if (recreate) await client.query(`CREATE DATABASE ${DB}`);
    await client.end();
  }
}

const portOpen = () => fetch(`http://localhost:${PORT}/health`).then(() => true, () => false);

async function startServer(env) {
  if (await portOpen()) throw new Error(`port ${PORT} is already in use — stop whatever runs there (or set E2E_PORT)`);
  // node itself (not pnpm/npx), so stopping it really stops the server
  const child = spawn(process.execPath, ["--import", "tsx", "src/server.ts"], {
    cwd: repo,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let log = "";
  child.stdout.on("data", (d) => (log += d));
  child.stderr.on("data", (d) => (log += d));
  for (let i = 0; i < 80; i++) {
    if (child.exitCode !== null) break;
    if (await fetch(`http://localhost:${PORT}/health`).then((r) => r.ok, () => false)) return { child, log: () => log };
    await new Promise((r) => setTimeout(r, 250));
  }
  child.kill();
  throw new Error(`server did not start:\n${log}`);
}

async function stopServer(server) {
  if (server.child.exitCode !== null) return;
  const exited = new Promise((r) => server.child.once("exit", r));
  server.child.kill("SIGTERM");
  await exited;
  for (let i = 0; i < 40 && (await portOpen()); i++) await new Promise((r) => setTimeout(r, 100));
}

function runSuite(file, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(here, `${file}.test.mjs`)], { cwd: repo, env: { ...process.env, ...env, BASE: `http://localhost:${PORT}`, REPO: repo } });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("exit", (code) => resolve({ ok: code === 0, out }));
  });
}

/** Secrets the suites created in the Key Vault emulator, and the test signing-key secret. */
async function cleanVault() {
  const url = dev.AZURE_KEYVAULT_URL;
  if (!url) return;
  for (const [k, v] of Object.entries(dev)) process.env[k] ??= v; // identity endpoint, TLS settings
  const { DefaultAzureCredential } = await import("@azure/identity");
  const { SecretClient } = await import("@azure/keyvault-secrets");
  const client = new SecretClient(url, new DefaultAzureCredential());
  for await (const p of client.listPropertiesOfSecrets()) {
    if (!/^e2e-/.test(p.name) && p.name !== KEYS_SECRET) continue;
    await (await client.beginDeleteSecret(p.name)).pollUntilDone();
    await client.purgeDeletedSecret(p.name).catch(() => {});
  }
}

// ------------------------------------------------------------------ run
const results = [];
for (const db of dbs) {
  const dbEnv = { AUTH_DB: db };
  for (const [name, { file, ...extra }] of suites) {
    const env = { ...baseEnv, ...dbEnv, ...extra };
    await resetDatabase(db);
    const server = await startServer(env);
    const started = Date.now();
    const { ok, out } = await runSuite(file ?? name, env);
    await stopServer(server);
    const passed = (out.match(/^PASS/gm) ?? []).length;
    const failed = (out.match(/^FAIL/gm) ?? []).length;
    console.log(`${ok ? "✓" : "✗"} ${db.padEnd(8)} ${name.padEnd(20)} ${passed} passed${failed ? `, ${failed} failed` : ""}  (${((Date.now() - started) / 1000).toFixed(1)}s)`);
    if (!ok) console.log(out.split("\n").filter((l) => !l.startsWith("PASS")).map((l) => `    ${l}`).join("\n") + `\n    --- server log ---\n${server.log().split("\n").slice(-20).map((l) => `    ${l}`).join("\n")}`);
    results.push(ok);
  }
}
for (const db of dbs) await resetDatabase(db, false).catch(() => {});
await cleanVault().catch((e) => console.warn(`vault cleanup skipped: ${e.message}`));
const failedCount = results.filter((r) => !r).length;
console.log(failedCount ? `\n${failedCount} of ${results.length} suite runs failed` : `\nall ${results.length} suite runs passed`);
process.exit(failedCount ? 1 : 0);
