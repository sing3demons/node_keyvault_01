import type { ISecretStore } from "./store";
import type { SecretSummary } from "./store";
export interface IKeyVaultService {
    getSecrets(): Promise<SecretSummary[]>;
    getSecret(name: string): Promise<string>;
    setSecret(name: string, value: string): Promise<void>;
    deleteSecret(name: string): Promise<void>;
}

export class KeyVaultService implements IKeyVaultService {

    constructor(private readonly store: ISecretStore) { }

    async getSecrets() {
        return this.store.listSecrets();
    }

    async getSecret(name: string) {
        
        return this.store.getSecret(name);
    }

    async setSecret(name: string, value: string) {
        return this.store.setSecret(name, value);
    }

    async deleteSecret(name: string) {
        return this.store.deleteSecret(name);
    }
}