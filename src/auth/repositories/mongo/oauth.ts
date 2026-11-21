// OAuth state: pending authorization requests, authorization codes, access / refresh tokens.

import type { Collection, Db } from "mongodb";
import type { AccessToken, AuthCode, AuthRequest, RefreshToken } from "../../model.js";
import type { AuthCodeRepository, AuthRequestRepository, TokenRepository } from "../../repository.js";
import { fromDoc, insertDoc, TTL, type Doc } from "./shared.js";

export class MongoAuthRequestRepository implements AuthRequestRepository {
  private readonly col: Collection<Doc<AuthRequest>>;

  constructor(db: Db) {
    this.col = db.collection("auth_requests");
  }

  create(r: AuthRequest): Promise<void> {
    return insertDoc(this.col, r, "Authorization request");
  }

  async findActive(id: string, now: Date): Promise<AuthRequest | null> {
    return fromDoc<AuthRequest>(await this.col.findOne({ _id: id, expiresAt: { $gt: now } }));
  }

  async consumeActive(id: string, now: Date): Promise<AuthRequest | null> {
    return fromDoc<AuthRequest>(await this.col.findOneAndDelete({ _id: id, expiresAt: { $gt: now } }));
  }

  async ensureIndexes(): Promise<void> {
    await this.col.createIndex({ expiresAt: 1 }, TTL);
  }
}

export class MongoAuthCodeRepository implements AuthCodeRepository {
  private readonly col: Collection<Doc<AuthCode>>;

  constructor(db: Db) {
    this.col = db.collection("auth_codes");
  }

  create(c: AuthCode): Promise<void> {
    return insertDoc(this.col, c, "Authorization code");
  }

  /** used=false -> true atomically: only one concurrent redeemer wins. */
  async redeem(id: string): Promise<AuthCode | null> {
    return fromDoc<AuthCode>(await this.col.findOneAndUpdate({ _id: id, used: false }, { $set: { used: true } }));
  }

  async find(id: string): Promise<AuthCode | null> {
    return fromDoc<AuthCode>(await this.col.findOne({ _id: id }));
  }

  async ensureIndexes(): Promise<void> {
    await this.col.createIndex({ expiresAt: 1 }, TTL);
  }
}

export class MongoTokenRepository implements TokenRepository {
  private readonly access$: Collection<Doc<AccessToken>>;
  private readonly refresh$: Collection<Doc<RefreshToken>>;

  constructor(db: Db) {
    this.access$ = db.collection("access_tokens");
    this.refresh$ = db.collection("refresh_tokens");
  }

  async createPair(access: AccessToken, refresh: RefreshToken | null): Promise<void> {
    await Promise.all([
      insertDoc(this.access$, access, "Access token"),
      ...(refresh ? [insertDoc(this.refresh$, refresh, "Refresh token")] : [])
    ]);
  }

  async findActiveAccess(id: string, now: Date): Promise<AccessToken | null> {
    return fromDoc<AccessToken>(await this.access$.findOne({ _id: id, expiresAt: { $gt: now } }));
  }

  async findAccess(id: string): Promise<AccessToken | null> {
    return fromDoc<AccessToken>(await this.access$.findOne({ _id: id }));
  }

  async findRefresh(id: string): Promise<RefreshToken | null> {
    return fromDoc<RefreshToken>(await this.refresh$.findOne({ _id: id }));
  }

  async rotateRefresh(id: string): Promise<RefreshToken | null> {
    return fromDoc<RefreshToken>(await this.refresh$.findOneAndUpdate({ _id: id, revoked: false }, { $set: { revoked: true } }));
  }

  revokeFamily(familyId: string): Promise<void> {
    return this.revokeWhere({ familyId });
  }

  revokeDevice(userId: string, deviceId: string): Promise<void> {
    return this.revokeWhere({ userId, deviceId });
  }

  revokeClient(clientId: string): Promise<void> {
    return this.revokeWhere({ clientId });
  }

  async activeDeviceIds(userId: string, now: Date): Promise<string[]> {
    const ids = await this.refresh$.distinct("deviceId", {
      userId,
      revoked: false,
      expiresAt: { $gt: now },
      deviceId: { $type: "string" }
    });
    return ids.map(String);
  }

  async ensureIndexes(): Promise<void> {
    await Promise.all([
      this.access$.createIndex({ expiresAt: 1 }, TTL),
      this.access$.createIndex({ familyId: 1 }),
      this.access$.createIndex({ userId: 1, deviceId: 1 }),
      this.refresh$.createIndex({ expiresAt: 1 }, TTL),
      this.refresh$.createIndex({ familyId: 1 }),
      this.refresh$.createIndex({ userId: 1, deviceId: 1 })
    ]);
  }

  /** Revoke matching refresh tokens and delete matching access tokens. */
  private async revokeWhere(filter: Record<string, string>): Promise<void> {
    await Promise.all([this.refresh$.updateMany(filter, { $set: { revoked: true } }), this.access$.deleteMany(filter)]);
  }
}
