// Recovery: re-enable the master credential (MASTER_CREDENTIALS) after it was disabled, for operators with
// access to the server when no client owner can sign in any more.
//   pnpm master:enable                 (dev)
//   node dist/cli/master-enable.js     (built image)

import { config } from "../config.js";
import { enableMasterDirectly } from "../auth/client-owners.js";
import { MasterAccountStore } from "../auth/master-account.js";
import { createAuthRepository } from "../auth/repositories/index.js";

async function main() {
  const repo = await createAuthRepository({
    driver: config.authDb,
    mongoUrl: config.mongoUrl,
    mongoDb: config.mongoDb,
    databaseUrl: config.databaseUrl,
    migrationsFolder: config.migrationsFolder
  });
  await repo.init();
  // same sync as a server start, so a new MASTER_CREDENTIALS (e.g. a reset password) applies too
  await new MasterAccountStore(repo).syncFromEnv(config.master);
  const account = await new MasterAccountStore(repo).get();
  if (!account) {
    await repo.close();
    throw new Error("There is no master account — set MASTER_CREDENTIALS, then run this again");
  }
  await enableMasterDirectly(repo);
  await repo.close();
  console.log(`Master account "${account.username}" is enabled again`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
