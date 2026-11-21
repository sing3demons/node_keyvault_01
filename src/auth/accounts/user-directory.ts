// The keyvault module's view of users (UserDirectory, src/keyvault/acl.ts), backed by the auth database.
// keyvault only needs to resolve "who" for owners and grants, so this reads id + username and nothing else.

import type { UserDirectory } from "../keyvault/acl.js";
import type { UserRef } from "./model.js";
import type { AuthRepository } from "./repository.js";

export class AuthUserDirectory implements UserDirectory {
  constructor(private readonly repo: AuthRepository) {}

  findByUsername(username: string): Promise<UserRef | null> {
    return this.repo.users.findRefByUsername(username);
  }

  /** One query for all ids (a secrets listing resolves every owner at once). */
  findByIds(ids: string[]): Promise<UserRef[]> {
    return this.repo.users.findRefs(ids);
  }
}
