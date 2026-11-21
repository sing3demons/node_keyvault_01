// Rotate the OIDC signing key now (e.g. suspected compromise), instead of waiting for OIDC_KEY_ROTATION_DAYS.
//   pnpm oidc:rotate                 (dev)
//   node dist/cli/rotate-oidc-key.js (built image)
// Running servers pick the new key up on their next sync (OIDC_KEYS_SYNC_SEC).

import { config } from "../config.js";
import { SigningKeyRing } from "../auth/oauth/oidc.js";
import { AzureKeyVaultSecretStore, NamedSecret } from "../keyvault/store.js";

async function main() {
  if (!config.azureVaultUrl) throw new Error("AZURE_KEYVAULT_URL is not set");
  const secret = new NamedSecret(new AzureKeyVaultSecretStore(config.azureVaultUrl), config.oidc.keysSecretName);
  const ring = new SigningKeyRing(secret, config.oidc);
  const { kid, retired } = await ring.rotate();
  console.log(`New active key: ${kid}`);
  console.log(retired.length ? `Still published (retired): ${retired.join(", ")}` : "No retired keys kept");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
