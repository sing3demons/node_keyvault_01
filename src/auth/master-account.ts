// The master account: bootstrap administrator of OAuth clients, kept in the database and synced at startup
// from MASTER_CREDENTIALS = base64("<username>:<password>|<email>:<alg>")   alg = argon2id | bcrypt
// The password part may be the plain password (hashed here with alg) or an already-made hash (pnpm master:create).
//
// Startup sync (syncFromEnv):
//   nothing stored                                  -> insert (username, email, hash of the password with alg)
//   same username + email + alg, password matches   -> keep
//   anything else (password changed, ...)           -> delete, insert the new one, end every master session
// Sign-in checks the stored account, so MASTER_CREDENTIALS can be emptied after the first start
// (no plain password left on disk); the stored account keeps working until disabled.

import { createHash, timingSafeEqual } from "node:crypto";
import { HASH_ALGORITHMS, hasherFor, type HashAlgorithm } from "../shared/hashing.js";
import { MASTER_CLIENT_ID } from "./model.js";
import type { AuthRepository } from "./repository.js";

const ACCOUNT_KEY = "master_account";
const MIN_PASSWORD = 16;

/** MASTER_CREDENTIALS, decoded. Exactly one of password / passwordHash is set. */
export interface MasterEnv {
  username: string;
  email: string;
  algorithm: HashAlgorithm;
  password?: string;
  passwordHash?: string;
}

/** What is stored (auth_settings / "master_account"). */
export interface MasterAccount {
  username: string;
  email: string;
  algorithm: HashAlgorithm;
  passwordHash: string;
  createdAt: string;
}

export type SyncResult = "created" | "kept" | "replaced" | "stored" | "none";

const looksLikeHash = (algorithm: HashAlgorithm, value: string) =>
  algorithm === "argon2id" ? value.startsWith("$argon2id$") : /^\$2[aby]\$\d\d\$.{53}$/.test(value);

/** Parses MASTER_CREDENTIALS; null when unset; throws on a malformed value so a typo cannot go unnoticed. */
export function parseMasterEnv(name: string, value: string | undefined): MasterEnv | null {
  if (!value?.trim()) return null;
  const v = value.trim();
  const help =
    `${name} must be base64("<username>:<password>|<email>:<alg>") with alg = ${HASH_ALGORITHMS.join(" | ")}` +
    ` (the password may also be a hash: pnpm master:create <username> <email> [alg])`;
  const decoded = Buffer.from(v, "base64").toString("utf8");
  if (Buffer.from(decoded, "utf8").toString("base64").replace(/=+$/, "") !== v.replace(/=+$/, "")) {
    throw new Error(`${name} is not valid base64. ${help}`);
  }
  // the email and alg contain no "|"; a plain password may, so split at the last one
  const bar = decoded.lastIndexOf("|");
  if (bar < 0) throw new Error(`${name} uses the old "username:password" format. ${help}`);
  const [userPart, emailPart] = [decoded.slice(0, bar), decoded.slice(bar + 1)];
  const userSep = userPart.indexOf(":");
  const algSep = emailPart.lastIndexOf(":");
  if (userSep < 1 || algSep < 1) throw new Error(`${name} is malformed. ${help}`);
  const username = userPart.slice(0, userSep);
  const secret = userPart.slice(userSep + 1);
  const email = emailPart.slice(0, algSep).trim().toLowerCase();
  const algorithm = emailPart.slice(algSep + 1).trim() as HashAlgorithm;
  if (!HASH_ALGORITHMS.includes(algorithm)) throw new Error(`${name}: unknown alg "${algorithm}". ${help}`);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error(`${name}: "${email}" is not an email address. ${help}`);
  if (looksLikeHash(algorithm, secret)) return { username, email, algorithm, passwordHash: secret };
  if (secret.startsWith("$argon2") || secret.startsWith("$2")) {
    throw new Error(`${name}: the password looks like a hash of another algorithm than "${algorithm}". ${help}`);
  }
  if (secret.length < MIN_PASSWORD) throw new Error(`${name}: the password must be at least ${MIN_PASSWORD} characters`);
  return { username, email, algorithm, password: secret };
}

export class MasterAccountStore {
  /** Hash of a random secret, checked when there is no account, so timing does not reveal that. */
  private readonly decoy = hasherFor("argon2id").hash(Math.random().toString(36));

  constructor(private readonly repo: AuthRepository) {}

  get(): Promise<MasterAccount | null> {
    return this.repo.settings.get<MasterAccount>(ACCOUNT_KEY);
  }

  /** Startup: make the stored account match MASTER_CREDENTIALS (see the header comment). */
  async syncFromEnv(env: MasterEnv | null): Promise<SyncResult> {
    const existing = await this.get();
    if (!env) return existing ? "stored" : "none";
    if (
      existing &&
      existing.username === env.username &&
      existing.email === env.email &&
      existing.algorithm === env.algorithm &&
      (await this.samePassword(existing, env))
    ) {
      return "kept";
    }
    // different password (or name / email / alg): replace it
    if (existing) await this.repo.settings.delete(ACCOUNT_KEY);
    const account: MasterAccount = {
      username: env.username,
      email: env.email,
      algorithm: env.algorithm,
      passwordHash: env.passwordHash ?? (await hasherFor(env.algorithm).hash(env.password!)),
      createdAt: new Date().toISOString()
    };
    await this.repo.settings.set(ACCOUNT_KEY, account);
    // sessions opened with the old password end now
    if (existing) await this.repo.tokens.revokeClient(MASTER_CLIENT_ID);
    return existing ? "replaced" : "created";
  }

  /** Username or email + password against the stored account. Always spends the hashing time. */
  async verify(identifier: string, password: string): Promise<MasterAccount | null> {
    const account = await this.get();
    if (!account) {
      await hasherFor("argon2id").verify(await this.decoy, password);
      return null;
    }
    const same = (a: string, b: string) =>
      timingSafeEqual(createHash("sha256").update(a).digest(), createHash("sha256").update(b).digest());
    const nameOk = same(identifier, account.username) || same(identifier.trim().toLowerCase(), account.email);
    const passOk = await hasherFor(account.algorithm).verify(account.passwordHash, password);
    return nameOk && passOk ? account : null;
  }

  private async samePassword(stored: MasterAccount, env: MasterEnv): Promise<boolean> {
    if (env.passwordHash !== undefined) {
      const a = Buffer.from(env.passwordHash);
      const b = Buffer.from(stored.passwordHash);
      return a.length === b.length && timingSafeEqual(a, b);
    }
    return hasherFor(stored.algorithm).verify(stored.passwordHash, env.password!);
  }
}
