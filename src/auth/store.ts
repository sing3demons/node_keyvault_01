import { ObjectId, type Collection, type Db } from "mongodb";

export interface UserDoc {
  _id: ObjectId;
  username: string;
  passwordHash: string;
  createdAt: Date;
}

export interface WebAuthnCredentialDoc {
  _id: ObjectId;
  userId: ObjectId;
  credId: string; // base64url
  publicKeyPem: string;
  counter: number;
  transports?: string[];
  name: string;
  createdAt: Date;
  lastUsedAt?: Date;
}

export interface WebAuthnChallengeDoc {
  _id: string;
  type: "register" | "login";
  challenge: string; // base64url
  userId?: ObjectId;
  authRequestId?: string;
  expiresAt: Date;
}

export interface AuthRequestDoc {
  _id: string;
  clientId: string;
  redirectUri: string;
  state?: string;
  scope: string;
  codeChallenge: string;
  expiresAt: Date;
}

export interface AuthCodeDoc {
  _id: string; // sha256(code)
  userId: ObjectId;
  clientId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string;
  familyId: string; // tokens issued from this code share it (replay => revoke)
  used: boolean;
  expiresAt: Date;
}

export interface AccessTokenDoc {
  _id: string; // sha256(token)
  userId: ObjectId;
  clientId: string;
  scope: string;
  familyId: string;
  expiresAt: Date;
}

export interface RefreshTokenDoc {
  _id: string; // sha256(token)
  userId: ObjectId;
  clientId: string;
  scope: string;
  familyId: string;
  revoked: boolean;
  expiresAt: Date;
}

/** Thin wrapper around the native driver collections used by auth. */
export class AuthStore {
  readonly users: Collection<UserDoc>;
  readonly credentials: Collection<WebAuthnCredentialDoc>;
  readonly challenges: Collection<WebAuthnChallengeDoc>;
  readonly authRequests: Collection<AuthRequestDoc>;
  readonly authCodes: Collection<AuthCodeDoc>;
  readonly accessTokens: Collection<AccessTokenDoc>;
  readonly refreshTokens: Collection<RefreshTokenDoc>;

  constructor(db: Db) {
    this.users = db.collection("users");
    this.credentials = db.collection("webauthn_credentials");
    this.challenges = db.collection("webauthn_challenges");
    this.authRequests = db.collection("auth_requests");
    this.authCodes = db.collection("auth_codes");
    this.accessTokens = db.collection("access_tokens");
    this.refreshTokens = db.collection("refresh_tokens");
  }

  async ensureIndexes(): Promise<void> {
    // TTL indexes: Mongo removes expired docs (sweeper runs ~every 60s, so expiry is also checked in code)
    const ttl = { expireAfterSeconds: 0 };
    await Promise.all([
      this.users.createIndex({ username: 1 }, { unique: true }),
      this.credentials.createIndex({ credId: 1 }, { unique: true }),
      this.credentials.createIndex({ userId: 1 }),
      this.challenges.createIndex({ expiresAt: 1 }, ttl),
      this.authRequests.createIndex({ expiresAt: 1 }, ttl),
      this.authCodes.createIndex({ expiresAt: 1 }, ttl),
      this.accessTokens.createIndex({ expiresAt: 1 }, ttl),
      this.accessTokens.createIndex({ familyId: 1 }),
      this.refreshTokens.createIndex({ expiresAt: 1 }, ttl),
      this.refreshTokens.createIndex({ familyId: 1 })
    ]);
  }
}
