import { HttpError } from "../shared/http.js";
import type { ISecretStore, SecretSummary } from "./store.js";

export interface IKeyVaultService {
  getSecrets(): Promise<SecretSummary[]>;
  getSecret(name: string): Promise<string>;
  setSecret(name: string, value: string): Promise<void>;
  deleteSecret(name: string): Promise<void>;
}

export class KeyVaultService implements IKeyVaultService {
  private readonly reserved: ReadonlySet<string>;

  /**
   * @param reservedNames secrets the system keeps in the same vault (e.g. OIDC signing keys). They are
   *   hidden from listing and cannot be read, written or deleted through this API.
   */
  constructor(
    private readonly store: ISecretStore,
    reservedNames: readonly string[] = []
  ) {
    // Key Vault secret names are case-insensitive
    this.reserved = new Set(reservedNames.map((n) => n.toLowerCase()));
  }

  async getSecrets() {
    return (await this.store.listSecrets()).filter((s) => !this.isReserved(s.name));
  }

  async getSecret(name: string) {
    this.assertNotReserved(name);
    return this.store.getSecret(name);
  }

  async setSecret(name: string, value: string) {
    this.assertNotReserved(name);
    return this.store.setSecret(name, value);
  }

  async deleteSecret(name: string) {
    this.assertNotReserved(name);
    return this.store.deleteSecret(name);
  }

  private isReserved(name: string): boolean {
    return this.reserved.has(name.toLowerCase());
  }

  private assertNotReserved(name: string): void {
    if (this.isReserved(name)) throw new HttpError(403, `"${name}" is reserved for the system`, "access_denied");
  }
}
