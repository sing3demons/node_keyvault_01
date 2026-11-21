// Who may manage OAuth clients: users holding the "client_admin" role ("owners"), plus the master
// account (stored in the DB, synced from MASTER_CREDENTIALS at startup) for bootstrapping. Once another owner exists the master can be
// disabled for good — stored in the database, so a leaked env value stops working even if it stays set.
// Invariant: at least one way in remains (an owner, or an enabled master).

import { HttpError } from "../shared/http.js";
import type { MasterAccountStore } from "./master-account.js";
import { MASTER_CLIENT_ID } from "./model.js";
import type { AuthRepository } from "./repository.js";

const ROLE = "client_admin";
const MASTER_KEY = "master_credential";

interface MasterState {
  disabledAt: string;
  disabledBy: string;
}

export interface OwnerView {
  id: string;
  username: string;
  email?: string;
}

export interface OwnersView {
  owners: OwnerView[];
  master: {
    /** A master account exists (stored in the DB, from MASTER_CREDENTIALS). */
    configured: boolean;
    username?: string;
    email?: string;
    /** Usable right now: configured and not disabled. */
    enabled: boolean;
    disabledAt?: string;
    disabledBy?: string;
  };
}

/** Who is calling: the master credential, or a signed-in owner. */
export type Actor = { kind: "master"; name: string } | { kind: "user"; id: string; username: string };

export class ClientOwnerService {
  constructor(
    private readonly repo: AuthRepository,
    private readonly masterAccounts: MasterAccountStore
  ) {}

  /** Checked on every master request (no caching: disabling takes effect at once on every instance). */
  async masterEnabled(): Promise<boolean> {
    return !!(await this.masterAccounts.get()) && !(await this.repo.settings.get<MasterState>(MASTER_KEY));
  }

  async view(): Promise<OwnersView> {
    const [state, account] = await Promise.all([this.repo.settings.get<MasterState>(MASTER_KEY), this.masterAccounts.get()]);
    return {
      owners: await this.owners(),
      master: {
        configured: !!account,
        ...(account ? { username: account.username, email: account.email } : {}),
        enabled: !!account && !state,
        ...(state ? { disabledAt: state.disabledAt, disabledBy: state.disabledBy } : {})
      }
    };
  }

  async addOwner(username: string): Promise<OwnersView> {
    const user = await this.repo.users.findByUsername(username.trim().toLowerCase());
    if (!user) throw new HttpError(404, `User "${username}" not found`);
    if (!user.roles.includes(ROLE)) await this.repo.users.setRoles(user.id, [...user.roles, ROLE]);
    return this.view();
  }

  /** Never leaves client management without a way in. */
  async removeOwner(username: string): Promise<OwnersView> {
    const user = await this.repo.users.findByUsername(username.trim().toLowerCase());
    if (!user || !user.roles.includes(ROLE)) throw new HttpError(404, `"${username}" is not an owner`);
    const others = (await this.owners()).filter((o) => o.id !== user.id);
    if (others.length === 0 && !(await this.masterEnabled())) {
      throw new HttpError(409, "Cannot remove the last owner while the master credential is disabled — add another owner first", "conflict");
    }
    await this.repo.users.setRoles(user.id, user.roles.filter((r) => r !== ROLE));
    return this.view();
  }

  /** "Delete" the master: needs at least one owner, so client management is never left without a way in. */
  async disableMaster(actor: Actor): Promise<OwnersView> {
    if (!(await this.masterEnabled())) throw new HttpError(409, "The master credential is already disabled", "conflict");
    if ((await this.owners()).length === 0) {
      throw new HttpError(409, "Add at least one owner before disabling the master credential", "conflict");
    }
    await this.repo.settings.set(MASTER_KEY, {
      disabledAt: new Date().toISOString(),
      disabledBy: actor.kind === "master" ? `master:${actor.name}` : actor.username
    } satisfies MasterState);
    await this.repo.tokens.revokeClient(MASTER_CLIENT_ID); // end every master session now
    return this.view();
  }

  /** Owners only (a disabled master cannot sign in to do it). */
  async enableMaster(actor: Actor): Promise<OwnersView> {
    if (actor.kind !== "user") throw new HttpError(403, "Only an owner can re-enable the master credential", "access_denied");
    if (!(await this.masterAccounts.get())) throw new HttpError(409, "There is no master account (set MASTER_CREDENTIALS and restart)", "conflict");
    await this.repo.settings.delete(MASTER_KEY);
    return this.view();
  }

  private async owners(): Promise<OwnerView[]> {
    return (await this.repo.users.list())
      .filter((u) => u.roles.includes(ROLE))
      .map((u) => ({ id: u.id, username: u.username, ...(u.email !== undefined ? { email: u.email } : {}) }));
  }
}

/** Recovery for operators with server access when every owner lost access: `pnpm master:enable`. */
export async function enableMasterDirectly(repo: AuthRepository): Promise<void> {
  await repo.settings.delete(MASTER_KEY);
}
