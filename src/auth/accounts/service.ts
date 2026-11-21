// User accounts: creating one, checking a password, the profile a user edits, and admin roles.

import { randomUUID } from "node:crypto";
import { HttpError } from "../../shared/http.js";
import type { SecretHasher } from "../../shared/hashing.js";
import { displayProfile, isPassword, type LocalizedProfile, type Role, type User, type UserSummary } from "../model.js";
import { DuplicateKeyError, type AuthRepository } from "../repository.js";
import type { RegisterBody, UpdateAccountBody } from "../schemas.js";

/** Public view of a user (never includes credentials). */
export interface Account {
  id: string;
  username: string;
  email?: string;
  /** The email address was confirmed with an emailed code. */
  emailVerified: boolean;
  profiles: LocalizedProfile[];
  preferredLang?: string;
  /** Profile in preferredLang, else the first one. */
  displayProfile?: LocalizedProfile;
  roles: Role[];
  createdAt: string;
}

/** Admin listing row. */
export interface UserView {
  id: string;
  username: string;
  email?: string;
  roles: Role[];
  createdAt: string;
}

/** What a new account is made of (registration input without the sign-in parts). */
export type NewAccount = Omit<RegisterBody, "request_id">;

export const toAccount = (u: User): Account => ({
  id: u.id,
  username: u.username,
  ...(u.email !== undefined ? { email: u.email } : {}),
  emailVerified: !!u.email && !!u.emailVerifiedAt,
  profiles: u.profiles,
  ...(u.preferredLang !== undefined ? { preferredLang: u.preferredLang } : {}),
  ...(displayProfile(u) ? { displayProfile: displayProfile(u) } : {}),
  roles: u.roles,
  createdAt: u.createdAt.toISOString()
});

const toUserView = (u: UserSummary): UserView => ({
  id: u.id,
  username: u.username,
  ...(u.email !== undefined ? { email: u.email } : {}),
  roles: u.roles,
  createdAt: u.createdAt.toISOString()
});

export class AccountService {
  constructor(
    private readonly repo: AuthRepository,
    private readonly hasher: SecretHasher,
    /** Bootstrap admins (ADMIN_USERNAMES), lowercased. */
    private readonly adminUsernames: readonly string[] = []
  ) {}

  // ---------------------------------------------------------------- accounts

  /** Input is already validated and normalized by `registerBody`. The email starts unverified. */
  async create({ username, email, password, profiles, preferredLang }: NewAccount): Promise<User> {
    const now = new Date();
    const user: User = {
      id: randomUUID(),
      username,
      email,
      profiles,
      ...(preferredLang !== undefined ? { preferredLang } : {}),
      credentials: [{ id: randomUUID(), type: "password", ...(await this.hasher.hash(password)), createdAt: now }],
      roles: this.adminUsernames.includes(username) ? ["admin"] : [],
      createdAt: now
    };
    try {
      await this.repo.users.create(user);
    } catch (error) {
      throw this.conflict(error);
    }
    return user;
  }

  /** `identifier` is a username, or an email address when it contains "@" (both already lowercased). */
  async verifyPassword(identifier: string, password: string): Promise<User> {
    const user = identifier.includes("@")
      ? await this.repo.users.findByEmail(identifier)
      : await this.repo.users.findByUsername(identifier);
    const credential = user?.credentials.find(isPassword);
    // runs even without a credential, so timing does not reveal whether the user exists
    const result = await this.hasher.verify(credential, password);
    if (!user || !credential || !result.ok) {
      throw new HttpError(401, "Invalid username, email or password", "access_denied");
    }
    if (result.needsRehash) {
      const { value, algorithm } = await this.hasher.hash(password);
      await this.repo.users.updateSecret(user.id, credential.id, value, algorithm);
    }
    return user;
  }

  async require(userId: string): Promise<User> {
    const user = await this.repo.users.findById(userId);
    if (!user) throw new HttpError(404, "User not found");
    return user;
  }

  // ---------------------------------------------------------------- profile (/auth/me)

  async get(userId: string): Promise<Account> {
    return toAccount(await this.require(userId));
  }

  /** Input is validated by `updateAccountBody`; preferredLang is re-checked against the stored profiles. */
  async update(userId: string, update: UpdateAccountBody): Promise<Account> {
    const user = await this.require(userId);
    // a new address has to be proven again
    const emailChanged = update.email !== undefined && update.email !== user.email;
    const profiles = update.profiles ?? user.profiles;
    let preferredLang = update.preferredLang;
    if (typeof preferredLang === "string" && !profiles.some((n) => n.lang === preferredLang)) {
      throw new HttpError(400, `preferredLang "${preferredLang}" is not one of your profile languages`);
    }
    // profiles replaced without the current preference => fall back to the first name
    if (preferredLang === undefined && user.preferredLang && !profiles.some((n) => n.lang === user.preferredLang)) {
      preferredLang = null;
    }
    try {
      await this.repo.users.updateAccount(userId, {
        ...update,
        preferredLang,
        ...(emailChanged ? { emailVerifiedAt: null } : {})
      });
    } catch (error) {
      throw this.conflict(error);
    }
    return this.get(userId);
  }

  // ---------------------------------------------------------------- roles (admin)

  /** Startup: give the admin role to ADMIN_USERNAMES users that already exist. */
  async bootstrapAdmins(): Promise<void> {
    for (const username of this.adminUsernames) {
      const user = await this.repo.users.findByUsername(username);
      if (user && !user.roles.includes("admin")) await this.repo.users.setRoles(user.id, [...user.roles, "admin"]);
    }
  }

  async list(): Promise<UserView[]> {
    return (await this.repo.users.list()).map(toUserView);
  }

  /**
   * Admin only (enforced by the route). The last admin cannot lose the role, so nobody gets locked out.
   * client_admin is not an admin's to give or take (see ClientOwnerService): it is kept as it is.
   */
  async setRoles(username: string, roles: Role[]): Promise<UserView> {
    const target = await this.repo.users.findByUsername(username.trim().toLowerCase());
    if (!target) throw new HttpError(404, `User "${username}" not found`);
    if (roles.includes("client_admin") !== target.roles.includes("client_admin")) {
      throw new HttpError(403, "client_admin is managed by client owners (Clients → Owners), not here", "access_denied");
    }
    const next = [...new Set(roles)];
    if (target.roles.includes("admin") && !next.includes("admin")) {
      const admins = (await this.repo.users.list()).filter((u) => u.roles.includes("admin"));
      if (admins.length <= 1) throw new HttpError(409, "Cannot remove the last admin", "conflict");
    }
    await this.repo.users.setRoles(target.id, next);
    return toUserView({ ...target, roles: next });
  }

  /** DuplicateKeyError -> 409 naming what is taken; anything else passes through. */
  private conflict(error: unknown): unknown {
    if (!(error instanceof DuplicateKeyError)) return error;
    if (error.field === "email") return new HttpError(409, "Email already registered");
    if (error.field === "username") return new HttpError(409, "Username already taken");
    return new HttpError(409, error.message);
  }
}
