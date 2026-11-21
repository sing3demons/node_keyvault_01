// Hashing of user secrets (password, PIN, recovery codes, ...) for storage.
// Only turns a secret into a stored hash and checks a secret against one;
// rules per secret type (length, attempt limits, ...) belong to the caller.

import argon2 from "argon2";
import bcrypt from "bcryptjs";
import { randomToken } from "./crypto.js";

/** New hashes use argon2id; other algorithms are only verified (then upgraded). */
export type HashAlgorithm = "argon2id" | "bcrypt";

export interface StoredHash {
  value: string; // encoded hash (PHC string)
  algorithm: HashAlgorithm;
}

export type VerifyResult = { ok: false } | { ok: true; needsRehash: boolean };

/** Checks hashes of one algorithm. Enough for legacy/imported hashes we only read. */
export interface SecretVerifier {
  readonly algorithm: HashAlgorithm;
  verify(hash: string, secret: string): Promise<boolean>;
  /** true when the hash should be replaced (outdated parameters) */
  needsRehash(hash: string): boolean;
}

/** An algorithm we also write new hashes with. */
export interface SecretHashAlgorithm extends SecretVerifier {
  hash(secret: string): Promise<string>;
}

export class Argon2idHasher implements SecretHashAlgorithm {
  readonly algorithm = "argon2id" as const;
  private readonly options = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

  hash(secret: string): Promise<string> {
    return argon2.hash(secret, this.options);
  }

  verify(hash: string, secret: string): Promise<boolean> {
    return argon2.verify(hash, secret).catch(() => false);
  }

  needsRehash(hash: string): boolean {
    return argon2.needsRehash(hash, this.options);
  }
}

/** bcrypt ($2a$ / $2b$ / $2y$), e.g. hashes from htpasswd -B or another system. */
export class BcryptHasher implements SecretHashAlgorithm {
  readonly algorithm = "bcrypt" as const;

  constructor(private readonly cost = 12) {}

  hash(secret: string): Promise<string> {
    return bcrypt.hash(secret, this.cost);
  }

  verify(hash: string, secret: string): Promise<boolean> {
    return bcrypt.compare(secret, hash).catch(() => false);
  }

  needsRehash(hash: string): boolean {
    return bcrypt.getRounds(hash) < this.cost;
  }
}

export const HASH_ALGORITHMS: readonly HashAlgorithm[] = ["argon2id", "bcrypt"];

/** Hasher for a given algorithm (only these two exist). */
export const hasherFor = (algorithm: HashAlgorithm): SecretHashAlgorithm =>
  algorithm === "bcrypt" ? new BcryptHasher() : new Argon2idHasher();

/**
 * Hashes new secrets with `primary`, and verifies hashes from `primary` or any `legacy` verifier
 * (e.g. bcrypt hashes imported from another system). A secret verified by a legacy algorithm,
 * or with outdated parameters, reports `needsRehash` so the caller can store a fresh hash.
 */
export class SecretHasher {
  private readonly verifiers: ReadonlyMap<HashAlgorithm, SecretVerifier>;
  /** Hash of a random secret, verified against when there is nothing to check (see verify). */
  private readonly decoy: Promise<string>;

  constructor(
    private readonly primary: SecretHashAlgorithm,
    legacy: SecretVerifier[] = []
  ) {
    this.verifiers = new Map([...legacy, primary].map((v) => [v.algorithm, v]));
    this.decoy = primary.hash(randomToken());
  }

  async hash(secret: string): Promise<StoredHash> {
    return { value: await this.primary.hash(secret), algorithm: this.primary.algorithm };
  }

  /**
   * `stored` is undefined when the user does not exist or has no credential of that type.
   * We still spend the same hashing time, so response timing does not reveal which case it was.
   */
  async verify(stored: StoredHash | undefined, secret: string): Promise<VerifyResult> {
    const verifier = stored && this.verifiers.get(stored.algorithm);
    if (!stored || !verifier) {
      await this.primary.verify(await this.decoy, secret);
      return { ok: false };
    }
    if (!(await verifier.verify(stored.value, secret))) {
      return { ok: false };
    }
    return { ok: true, needsRehash: verifier !== this.primary || verifier.needsRehash(stored.value) };
  }
}
