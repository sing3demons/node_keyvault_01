// OAuth state: pending authorization requests, authorization codes, access / refresh tokens.

import { and, eq, gt, isNotNull, lt, ne } from "drizzle-orm";
import type { AccessToken, AuthCode, AuthRequest, RefreshToken } from "../../model.js";
import type { AuthCodeRepository, AuthRequestRepository, TokenRepository } from "../../repository.js";
import { accessTokens, authCodes, authRequests, refreshTokens } from "./schema.js";
import { clean, isUuid, write, type Db, type Tx } from "./shared.js";

export class DrizzleAuthRequestRepository implements AuthRequestRepository {
  constructor(private readonly db: Db) {}

  create(r: AuthRequest): Promise<void> {
    return write("Authorization request", () => this.db.insert(authRequests).values(r));
  }

  async findActive(id: string, now: Date): Promise<AuthRequest | null> {
    const [row] = await this.db.select().from(authRequests).where(and(eq(authRequests.id, id), gt(authRequests.expiresAt, now)));
    return clean<AuthRequest>(row);
  }

  async consumeActive(id: string, now: Date): Promise<AuthRequest | null> {
    const [row] = await this.db.delete(authRequests).where(and(eq(authRequests.id, id), gt(authRequests.expiresAt, now))).returning();
    return clean<AuthRequest>(row);
  }

  async purgeExpired(tx: Tx, now: Date): Promise<void> {
    await tx.delete(authRequests).where(lt(authRequests.expiresAt, now));
  }
}

export class DrizzleAuthCodeRepository implements AuthCodeRepository {
  constructor(private readonly db: Db) {}

  create(c: AuthCode): Promise<void> {
    return write("Authorization code", () => this.db.insert(authCodes).values(c));
  }

  /** UPDATE ... WHERE used = false RETURNING => only one concurrent redeemer wins. */
  async redeem(id: string): Promise<AuthCode | null> {
    const [row] = await this.db
      .update(authCodes)
      .set({ used: true })
      .where(and(eq(authCodes.id, id), eq(authCodes.used, false)))
      .returning();
    return clean<AuthCode>(row);
  }

  async find(id: string): Promise<AuthCode | null> {
    return clean<AuthCode>((await this.db.select().from(authCodes).where(eq(authCodes.id, id)))[0]);
  }

  async purgeExpired(tx: Tx, now: Date): Promise<void> {
    await tx.delete(authCodes).where(lt(authCodes.expiresAt, now));
  }
}

export class DrizzleTokenRepository implements TokenRepository {
  constructor(private readonly db: Db) {}

  createPair(access: AccessToken, refresh: RefreshToken | null): Promise<void> {
    return write("Token", () =>
      this.db.transaction(async (tx) => {
        await tx.insert(accessTokens).values(access);
        if (refresh) await tx.insert(refreshTokens).values(refresh);
      })
    );
  }

  async findActiveAccess(id: string, now: Date): Promise<AccessToken | null> {
    const [row] = await this.db.select().from(accessTokens).where(and(eq(accessTokens.id, id), gt(accessTokens.expiresAt, now)));
    return clean<AccessToken>(row);
  }

  async findAccess(id: string): Promise<AccessToken | null> {
    return clean<AccessToken>((await this.db.select().from(accessTokens).where(eq(accessTokens.id, id)))[0]);
  }

  async findRefresh(id: string): Promise<RefreshToken | null> {
    return clean<RefreshToken>((await this.db.select().from(refreshTokens).where(eq(refreshTokens.id, id)))[0]);
  }

  async rotateRefresh(id: string): Promise<RefreshToken | null> {
    const [row] = await this.db
      .update(refreshTokens)
      .set({ revoked: true })
      .where(and(eq(refreshTokens.id, id), eq(refreshTokens.revoked, false)))
      .returning();
    return clean<RefreshToken>(row);
  }

  async revokeFamily(familyId: string): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.update(refreshTokens).set({ revoked: true }).where(eq(refreshTokens.familyId, familyId));
      await tx.delete(accessTokens).where(eq(accessTokens.familyId, familyId));
    });
  }

  async revokeDevice(userId: string, deviceId: string): Promise<void> {
    if (!isUuid(userId) || !isUuid(deviceId)) return;
    await this.db.transaction(async (tx) => {
      await tx
        .update(refreshTokens)
        .set({ revoked: true })
        .where(and(eq(refreshTokens.userId, userId), eq(refreshTokens.deviceId, deviceId)));
      await tx.delete(accessTokens).where(and(eq(accessTokens.userId, userId), eq(accessTokens.deviceId, deviceId)));
    });
  }

  async revokeUser(userId: string, exceptFamilyId?: string): Promise<void> {
    if (!isUuid(userId)) return;
    await this.db.transaction(async (tx) => {
      await tx
        .update(refreshTokens)
        .set({ revoked: true })
        .where(and(eq(refreshTokens.userId, userId), exceptFamilyId !== undefined ? ne(refreshTokens.familyId, exceptFamilyId) : undefined));
      await tx
        .delete(accessTokens)
        .where(and(eq(accessTokens.userId, userId), exceptFamilyId !== undefined ? ne(accessTokens.familyId, exceptFamilyId) : undefined));
    });
  }

  async revokeClient(clientId: string): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.update(refreshTokens).set({ revoked: true }).where(eq(refreshTokens.clientId, clientId));
      await tx.delete(accessTokens).where(eq(accessTokens.clientId, clientId));
    });
  }

  async activeDeviceIds(userId: string, now: Date): Promise<string[]> {
    if (!isUuid(userId)) return [];
    const rows = await this.db
      .selectDistinct({ deviceId: refreshTokens.deviceId })
      .from(refreshTokens)
      .where(
        and(
          eq(refreshTokens.userId, userId),
          eq(refreshTokens.revoked, false),
          gt(refreshTokens.expiresAt, now),
          isNotNull(refreshTokens.deviceId)
        )
      );
    return rows.flatMap((r) => (r.deviceId ? [r.deviceId] : []));
  }

  async purgeExpired(tx: Tx, now: Date): Promise<void> {
    await tx.delete(accessTokens).where(lt(accessTokens.expiresAt, now));
    await tx.delete(refreshTokens).where(lt(refreshTokens.expiresAt, now));
  }
}
