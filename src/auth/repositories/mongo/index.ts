// MongoDB (native driver) implementation of AuthRepository: one repository per collection group,
// each owning its indexes. Expiry uses TTL indexes.

import { MongoClient, type Db } from "mongodb";
import type { AuthRepository } from "../../repository.js";
import { MongoChallengeRepository, MongoEmailChallengeRepository } from "./challenges.js";
import { MongoClientRepository } from "./clients.js";
import { MongoDeviceRepository } from "./devices.js";
import { MongoAuthCodeRepository, MongoAuthRequestRepository, MongoTokenRepository } from "./oauth.js";
import { MongoSettingsRepository } from "./settings.js";
import { MongoUserRepository } from "./users.js";

export class MongoAuthRepository implements AuthRepository {
  readonly users: MongoUserRepository;
  readonly challenges: MongoChallengeRepository;
  readonly emailChallenges: MongoEmailChallengeRepository;
  readonly devices: MongoDeviceRepository;
  readonly clients: MongoClientRepository;
  readonly settings: MongoSettingsRepository;
  readonly authRequests: MongoAuthRequestRepository;
  readonly authCodes: MongoAuthCodeRepository;
  readonly tokens: MongoTokenRepository;

  static async connect(url: string, dbName: string): Promise<MongoAuthRepository> {
    const client = new MongoClient(url);
    await client.connect();
    return new MongoAuthRepository(client, client.db(dbName));
  }

  constructor(
    private readonly client: MongoClient,
    db: Db
  ) {
    this.users = new MongoUserRepository(db);
    this.challenges = new MongoChallengeRepository(db);
    this.emailChallenges = new MongoEmailChallengeRepository(db);
    this.devices = new MongoDeviceRepository(db);
    this.clients = new MongoClientRepository(db);
    this.settings = new MongoSettingsRepository(db);
    this.authRequests = new MongoAuthRequestRepository(db);
    this.authCodes = new MongoAuthCodeRepository(db);
    this.tokens = new MongoTokenRepository(db);
  }

  /** Legacy-layout upgrade (users) and every collection's indexes. */
  async init(): Promise<void> {
    await this.users.ensureIndexes();
    await Promise.all([
      this.challenges.ensureIndexes(),
      this.emailChallenges.ensureIndexes(),
      this.devices.ensureIndexes(),
      this.authRequests.ensureIndexes(),
      this.authCodes.ensureIndexes(),
      this.tokens.ensureIndexes()
    ]);
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}
