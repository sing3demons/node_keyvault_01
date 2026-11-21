// Ownership and sharing of Key Vault secrets. The values stay in Key Vault; who may do what is
// kept in the app database (see repositories/). Everyone signed in sees every secret's name;
// the value and changes need ownership or a grant from the owner.

/** What a grant allows besides seeing the name. */
export const PERMISSIONS = ["read", "write", "delete"] as const;
export type Permission = (typeof PERMISSIONS)[number];

export interface SecretGrant {
  userId: string;
  permissions: Permission[];
}

export interface SecretAcl {
  /** Key Vault secret name, lowercased (vault names are case-insensitive). */
  name: string;
  ownerId: string;
  grants: SecretGrant[];
  createdAt: Date;
}

/** Who is acting. Admins may transfer ownership of any secret, nothing more (least privilege). */
export interface Actor {
  id: string;
  isAdmin: boolean;
}

/** What the current user may do with one secret. */
export interface Access {
  owner: boolean;
  read: boolean;
  write: boolean;
  delete: boolean;
  /** Change grants (owner only). */
  share: boolean;
  /** Hand ownership to another user (owner, or an admin). */
  transfer: boolean;
}

export function accessFor(acl: SecretAcl, actor: Actor): Access {
  if (acl.ownerId === actor.id) return { owner: true, read: true, write: true, delete: true, share: true, transfer: true };
  const granted = new Set(acl.grants.find((g) => g.userId === actor.id)?.permissions ?? []);
  return {
    owner: false,
    read: granted.has("read"),
    write: granted.has("write"),
    delete: granted.has("delete"),
    share: false,
    transfer: actor.isAdmin
  };
}

export const aclKey = (secretName: string): string => secretName.toLowerCase();

/** Storage for ACLs. Implementations: repositories/mongo.ts, repositories/drizzle.ts */
export interface SecretAclRepository {
  /** @throws SecretAclExistsError when an ACL for the name already exists (someone else created it first) */
  create(acl: SecretAcl): Promise<void>;
  find(name: string): Promise<SecretAcl | null>;
  findMany(names: string[]): Promise<SecretAcl[]>;
  /** Sets (or replaces) one user's permissions; an empty list removes the grant. */
  setGrant(name: string, userId: string, permissions: Permission[]): Promise<void>;
  /** New owner; any grant the new owner had is dropped (ownership covers it). */
  setOwner(name: string, ownerId: string): Promise<void>;
  delete(name: string): Promise<void>;
  init(): Promise<void>;
  close(): Promise<void>;
}

export class SecretAclExistsError extends Error {
  constructor(name: string) {
    super(`Secret "${name}" already has an owner`);
  }
}

/** Looks users up for sharing (by username) and for showing owners/grantees (by id). */
export interface UserDirectory {
  findByUsername(username: string): Promise<{ id: string; username: string } | null>;
  findByIds(ids: string[]): Promise<{ id: string; username: string }[]>;
}
