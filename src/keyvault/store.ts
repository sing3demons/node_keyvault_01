import { DefaultAzureCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";

export interface SecretSummary {
    name: string;
    enabled: boolean;
    createdOn?: string;
    updatedOn?: string;
}

export interface ISecretStore {
    listSecrets(): Promise<SecretSummary[]>;
    getSecret(name: string): Promise<string>;
    setSecret(name: string, value: string): Promise<void>;
    deleteSecret(name: string): Promise<void>;
}


export class AzureKeyVaultSecretStore implements ISecretStore {
    private readonly client: SecretClient;

    constructor(vaultUrl: string) {
        this.client = new SecretClient(vaultUrl, new DefaultAzureCredential());
    }

    async listSecrets(): Promise<SecretSummary[]> {
        const secrets: SecretSummary[] = [];
        for await (const props of this.client.listPropertiesOfSecrets()) {
            secrets.push({
                name: props.name,
                enabled: props.enabled ?? true,
                createdOn: props.createdOn?.toISOString(),
                updatedOn: props.updatedOn?.toISOString()
            });
        }
        return secrets.sort((a, b) => a.name.localeCompare(b.name));
    }

    async getSecret(name: string): Promise<string> {
        const response = await this.client.getSecret(name);
        if (!response.value) {
            throw new Error(`Secret "${name}" exists but has no value.`);
        }
        return response.value;
    }

    async setSecret(name: string, value: string): Promise<void> {
        try {
            await this.client.setSecret(name, value);
        } catch (error) {
            // 409: name is held by a soft-deleted secret -> recover it, then write the new value
            if ((error as { statusCode?: number }).statusCode !== 409) {
                throw error;
            }
            const poller = await this.client.beginRecoverDeletedSecret(name);
            await poller.pollUntilDone();
            await this.client.setSecret(name, value);
        }
    }

    async deleteSecret(name: string): Promise<void> {
        const poller = await this.client.beginDeleteSecret(name);
        await poller.pollUntilDone();
    }
}