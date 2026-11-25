import type { ISecretStore } from "./store";
import type { SecretSummary, SetSecretOptions } from "./store";
import { generateRsaKeyPair, type RsaKeyPairOptions } from "./keypair";

export interface GeneratedKeyPair {
    kid: string;
    privateSecretName: string;
    publicSecretName: string;
    expiresOn: string;
    /** public JWKS — safe to return to the caller; the private key never leaves Key Vault */
    jwks: unknown;
}

export interface IKeyVaultService {
    getSecrets(): Promise<SecretSummary[]>;
    getSecret(name: string): Promise<string>;
    setSecret(name: string, value: string, options?: SetSecretOptions): Promise<void>;
    deleteSecret(name: string): Promise<void>;
    generateKeyPair(name: string, options?: RsaKeyPairOptions): Promise<GeneratedKeyPair>;
}

export class KeyVaultService implements IKeyVaultService {

    constructor(private readonly store: ISecretStore) { }

    async getSecrets() {
        return this.store.listSecrets();
    }

    async getSecret(name: string) {
        
        return this.store.getSecret(name);
    }

    async setSecret(name: string, value: string, options?: SetSecretOptions) {
        return this.store.setSecret(name, value, options);
    }

    async deleteSecret(name: string) {
        return this.store.deleteSecret(name);
    }

    /** Generates an RSA key pair and stores it as two secrets: `<name>-private` and `<name>-public`. */
    async generateKeyPair(name: string, options?: RsaKeyPairOptions): Promise<GeneratedKeyPair> {
        const { kid, privateValue, publicValue, expiresOn } = generateRsaKeyPair(options);
        const privateSecretName = `${name}-private`;
        const publicSecretName = `${name}-public`;

        await this.store.setSecret(privateSecretName, privateValue, { expiresOn });
        await this.store.setSecret(publicSecretName, publicValue, { expiresOn });

        return {
            kid,
            privateSecretName,
            publicSecretName,
            expiresOn: expiresOn.toISOString(),
            jwks: JSON.parse(publicValue)
        };
    }
}