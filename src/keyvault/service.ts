import { HttpError } from "../shared/http.js";
import {
  accessFor,
  aclKey,
  SecretAclExistsError,
  type Access,
  type Actor,
  type Permission,
  type SecretAcl,
  type SecretAclRepository,
  type UserDirectory
} from "./acl.js";
import type { ISecretStore, SecretSummary } from "./store.js";

export interface UserRef {
  id: string;
  username: string;
}

/** A secret as the current user sees it: always the name and metadata, never the value. */
export interface SecretView extends SecretSummary {
  owner: UserRef | null;
  access: Access;
}

export interface GrantView {
  user: UserRef;
  permissions: Permission[];
}

export interface IKeyVaultService {
  getSecrets(actor: Actor): Promise<SecretView[]>;
  getSecret(actor: Actor, name: string): Promise<string>;
  setSecret(actor: Actor, name: string, value: string): Promise<{ created: boolean }>;
  deleteSecret(actor: Actor, name: string): Promise<void>;
  getGrants(actor: Actor, name: string): Promise<GrantView[]>;
  setGrant(actor: Actor, name: string, username: string, permissions: Permission[]): Promise<GrantView[]>;
  transferOwnership(actor: Actor, name: string, username: string): Promise<{ owner: UserRef }>;
}

/**
 * Secrets with per-secret ownership. The creator owns a secret and can read, change, delete and
 * share it; other users see only its name unless the owner granted read / write / delete.
 * Vault secrets without an owner record (made outside this app) are not exposed at all.
 */
export class KeyVaultService implements IKeyVaultService {
  private readonly reserved: ReadonlySet<string>;

  /**
   * @param reservedNames secrets the system keeps in the same vault (e.g. OIDC signing keys). They are
   *   hidden from listing and cannot be read, written or deleted through this API.
   */
  constructor(
    private readonly store: ISecretStore,
    private readonly acls: SecretAclRepository,
    private readonly users: UserDirectory,
    reservedNames: readonly string[] = []
  ) {
    this.reserved = new Set(reservedNames.map(aclKey));
  }

  async getSecrets(actor: Actor): Promise<SecretView[]> {
    const secrets = (await this.store.listSecrets()).filter((s) => !this.isReserved(s.name));
    const acls = new Map((await this.acls.findMany(secrets.map((s) => aclKey(s.name)))).map((a) => [a.name, a]));
    const owners = await this.usernames([...acls.values()].map((a) => a.ownerId));
    return secrets.flatMap((s) => {
      const acl = acls.get(aclKey(s.name));
      if (!acl) return []; // not managed by this app
      return [{ ...s, owner: owners.get(acl.ownerId) ?? null, access: accessFor(acl, actor) }];
    });
  }

  async getSecret(actor: Actor, name: string): Promise<string> {
    await this.require(actor, name, "read");
    return this.store.getSecret(name);
  }

  /** Creates the secret (caller becomes owner) or updates it (needs write). */
  async setSecret(actor: Actor, name: string, value: string): Promise<{ created: boolean }> {
    this.assertNotReserved(name);
    const existing = await this.acls.find(aclKey(name));
    if (existing) {
      this.check(existing, actor, "write", name);
      await this.store.setSecret(name, value);
      return { created: false };
    }
    if (await this.existsInVault(name)) {
      // a vault secret nobody owns here must not be taken over by whoever writes it first
      throw new HttpError(409, `Secret "${name}" exists in Key Vault but is not managed by this app`, "conflict");
    }
    try {
      await this.acls.create({ name: aclKey(name), ownerId: actor.id, grants: [], createdAt: new Date() });
    } catch (error) {
      if (error instanceof SecretAclExistsError) {
        throw new HttpError(409, `Secret "${name}" already exists`, "conflict"); // lost a race to create it
      }
      throw error;
    }
    try {
      await this.store.setSecret(name, value);
    } catch (error) {
      await this.acls.delete(aclKey(name)); // undo the claim so the name is not stuck
      throw error;
    }
    return { created: true };
  }

  async deleteSecret(actor: Actor, name: string): Promise<void> {
    await this.require(actor, name, "delete");
    await this.store.deleteSecret(name);
    await this.acls.delete(aclKey(name));
  }

  /** Owner only. */
  async getGrants(actor: Actor, name: string): Promise<GrantView[]> {
    const acl = await this.require(actor, name, "share");
    return this.grantViews(acl);
  }

  /** Owner only. Empty `permissions` revokes the user's grant. */
  async setGrant(actor: Actor, name: string, username: string, permissions: Permission[]): Promise<GrantView[]> {
    await this.require(actor, name, "share");
    const grantee = await this.users.findByUsername(username.trim().toLowerCase());
    if (!grantee) throw new HttpError(404, `User "${username}" not found`);
    if (grantee.id === actor.id) throw new HttpError(400, "You already own this secret");
    await this.acls.setGrant(aclKey(name), grantee.id, [...new Set(permissions)]);
    return this.grantViews((await this.acls.find(aclKey(name)))!);
  }

  /**
   * Owner hands the secret to someone else, or an admin reassigns it (e.g. the owner left).
   * The previous owner keeps no access unless the new owner shares it back.
   */
  async transferOwnership(actor: Actor, name: string, username: string): Promise<{ owner: UserRef }> {
    const acl = await this.require(actor, name, "transfer");
    const target = await this.users.findByUsername(username.trim().toLowerCase());
    if (!target) throw new HttpError(404, `User "${username}" not found`);
    if (target.id === acl.ownerId) throw new HttpError(400, `@${target.username} already owns "${name}"`);
    if (target.id === actor.id && acl.ownerId !== actor.id) {
      // otherwise "transfer only" would let an admin take any secret and read it
      throw new HttpError(403, "Admins cannot transfer a secret to themselves", "access_denied");
    }
    await this.acls.setOwner(acl.name, target.id);
    return { owner: target };
  }

  // ---------------------------------------------------------------- helpers

  private async require(actor: Actor, name: string, action: keyof Omit<Access, "owner">): Promise<SecretAcl> {
    this.assertNotReserved(name);
    const acl = await this.acls.find(aclKey(name));
    if (!acl) throw new HttpError(404, `Secret "${name}" not found`);
    this.check(acl, actor, action, name);
    return acl;
  }

  private check(acl: SecretAcl, actor: Actor, action: keyof Omit<Access, "owner">, name: string): void {
    if (!accessFor(acl, actor)[action]) {
      const what = { read: "read", write: "change", delete: "delete", share: "manage access to", transfer: "transfer" }[action];
      throw new HttpError(403, `You don't have permission to ${what} "${name}"`, "access_denied");
    }
  }

  private async existsInVault(name: string): Promise<boolean> {
    try {
      await this.store.getSecret(name);
      return true;
    } catch (error) {
      if ((error as { statusCode?: number }).statusCode === 404) return false;
      throw error;
    }
  }

  private async grantViews(acl: SecretAcl): Promise<GrantView[]> {
    const names = await this.usernames(acl.grants.map((g) => g.userId));
    return acl.grants.flatMap((g) => {
      const user = names.get(g.userId);
      return user ? [{ user, permissions: g.permissions }] : []; // grantee account was deleted
    });
  }

  private async usernames(ids: string[]): Promise<Map<string, UserRef>> {
    const unique = [...new Set(ids)];
    return new Map((await this.users.findByIds(unique)).map((u) => [u.id, u]));
  }

  private isReserved(name: string): boolean {
    return this.reserved.has(aclKey(name));
  }

  private assertNotReserved(name: string): void {
    if (this.isReserved(name)) throw new HttpError(403, `"${name}" is reserved for the system`, "access_denied");
  }
}
