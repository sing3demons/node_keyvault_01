import { Fido2Lib } from "fido2-lib";
import { randomUUID } from "node:crypto";
import { fromBase64Url, randomToken, toBase64Url } from "./crypto.js";
import { HttpError } from "./errors.js";
import { DuplicateKeyError, type AuthRepository, type WebAuthnCredential } from "./repository.js";

export interface WebAuthnSettings {
  rpId: string;
  rpName: string;
  origins: string[];
}

/** JSON shape the browser sends back (all binary fields base64url). */
export interface CredentialJSON {
  id: string;
  rawId: string;
  type: "public-key";
  transports?: string[];
  response: {
    clientDataJSON: string;
    attestationObject?: string;
    authenticatorData?: string;
    signature?: string;
    userHandle?: string | null;
  };
}

// UUID (current) or 24-hex ObjectId (credentials created by the earlier Mongo-only version)
const UUID_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})$/i;
const CHALLENGE_TTL_MS = 5 * 60_000;
const later = (ms: number) => new Date(Date.now() + ms);
/** WebAuthn user.id / userHandle = UTF-8 bytes of the user's id. */
const userHandleOf = (userId: string) => Buffer.from(userId, "utf8").toString("base64url");

export class WebAuthnService {
  private readonly fido: Fido2Lib;

  constructor(
    private readonly repo: AuthRepository,
    private readonly settings: WebAuthnSettings
  ) {
    this.fido = new Fido2Lib({
      timeout: CHALLENGE_TTL_MS,
      rpId: settings.rpId,
      rpName: settings.rpName,
      challengeSize: 32,
      attestation: "none",
      cryptoParams: [-7, -257], // ES256, RS256
      authenticatorRequireResidentKey: true, // discoverable credential => username-less sign-in
      authenticatorUserVerification: "preferred"
    });
  }

  // ---------------------------------------------------------------- registration (signed-in user)

  async registrationOptions(userId: string, username: string) {
    const existing = await this.repo.credentials.listByUser(userId);
    const options = await this.fido.attestationOptions();
    const challenge = toBase64Url(options.challenge);
    const challengeId = randomToken(16);
    await this.repo.challenges.create({
      id: challengeId,
      type: "register",
      challenge,
      userId,
      expiresAt: later(CHALLENGE_TTL_MS)
    });
    return {
      challengeId,
      publicKey: {
        rp: options.rp,
        user: { id: userHandleOf(userId), name: username, displayName: username },
        challenge,
        pubKeyCredParams: options.pubKeyCredParams,
        timeout: options.timeout,
        attestation: options.attestation,
        authenticatorSelection: { ...options.authenticatorSelection, residentKey: "required" },
        excludeCredentials: existing.map((c) => ({ type: "public-key", id: c.credId, transports: c.transports }))
      }
    };
  }

  async verifyRegistration(userId: string, challengeId: unknown, credential: CredentialJSON, name?: unknown) {
    const stored = await this.consumeChallenge(challengeId, "register");
    if (stored.userId !== userId) {
      throw new HttpError(400, "Challenge does not belong to this user");
    }
    if (!credential?.rawId || !credential.response?.attestationObject || !credential.response.clientDataJSON) {
      throw new HttpError(400, "Malformed credential");
    }
    let result;
    try {
      result = await this.fido.attestationResult(
        {
          rawId: fromBase64Url(credential.rawId),
          transports: credential.transports,
          response: {
            clientDataJSON: credential.response.clientDataJSON,
            attestationObject: credential.response.attestationObject
          }
        },
        { challenge: stored.challenge, origin: this.settings.origins, rpId: this.settings.rpId, factor: "either" }
      );
    } catch (error) {
      throw new HttpError(400, `Passkey registration failed: ${(error as Error).message}`);
    }
    const doc: WebAuthnCredential = {
      id: randomUUID(),
      userId,
      credId: toBase64Url(result.authnrData.get("credId") as ArrayBuffer),
      publicKeyPem: result.authnrData.get("credentialPublicKeyPem") as string,
      counter: Number(result.authnrData.get("counter") ?? 0),
      transports: credential.transports,
      name: typeof name === "string" && name.trim() ? name.trim().slice(0, 64) : "Passkey",
      createdAt: new Date()
    };
    try {
      await this.repo.credentials.create(doc);
    } catch (error) {
      if (error instanceof DuplicateKeyError) throw new HttpError(409, "Passkey already registered");
      throw error;
    }
    return { id: doc.id, name: doc.name, createdAt: doc.createdAt.toISOString() };
  }

  // ---------------------------------------------------------------- authentication (during /oauth/authorize)

  async loginOptions(authRequestId: string) {
    const options = await this.fido.assertionOptions();
    const challenge = toBase64Url(options.challenge);
    const challengeId = randomToken(16);
    await this.repo.challenges.create({
      id: challengeId,
      type: "login",
      challenge,
      authRequestId,
      expiresAt: later(CHALLENGE_TTL_MS)
    });
    return {
      challengeId,
      publicKey: {
        challenge,
        rpId: this.settings.rpId,
        timeout: options.timeout,
        userVerification: options.userVerification ?? "preferred"
        // no allowCredentials => browser offers discoverable passkeys
      }
    };
  }

  /** Verifies an assertion and returns the authenticated user's id. */
  async verifyLogin(challengeId: unknown, authRequestId: string, credential: CredentialJSON): Promise<string> {
    const stored = await this.consumeChallenge(challengeId, "login");
    if (stored.authRequestId !== authRequestId) {
      throw new HttpError(400, "Challenge does not belong to this authorization request");
    }
    const r = credential?.response;
    if (!credential?.rawId || !r?.clientDataJSON || !r.authenticatorData || !r.signature) {
      throw new HttpError(400, "Malformed credential");
    }
    const cred = await this.repo.credentials.findByCredId(credential.rawId);
    if (!cred) {
      throw new HttpError(401, "Unknown passkey");
    }
    let result;
    try {
      result = await this.fido.assertionResult(
        {
          rawId: fromBase64Url(credential.rawId),
          response: {
            clientDataJSON: r.clientDataJSON,
            authenticatorData: r.authenticatorData,
            signature: r.signature,
            userHandle: r.userHandle ?? undefined
          }
        },
        {
          challenge: stored.challenge,
          origin: this.settings.origins,
          rpId: this.settings.rpId,
          factor: "either",
          publicKey: cred.publicKeyPem,
          prevCounter: cred.counter,
          userHandle: userHandleOf(cred.userId)
        }
      );
    } catch (error) {
      throw new HttpError(401, `Passkey verification failed: ${(error as Error).message}`);
    }
    await this.repo.credentials.recordUse(
      cred.id,
      Number(result.authnrData.get("counter") ?? cred.counter),
      new Date()
    );
    return cred.userId;
  }

  // ---------------------------------------------------------------- management

  async list(userId: string) {
    const creds = await this.repo.credentials.listByUser(userId);
    return creds.map((c) => ({
      id: c.id,
      name: c.name,
      createdAt: c.createdAt.toISOString(),
      lastUsedAt: c.lastUsedAt?.toISOString()
    }));
  }

  async remove(userId: string, id: string): Promise<void> {
    if (!UUID_RE.test(id) || !(await this.repo.credentials.delete(userId, id))) throw new HttpError(404, "Passkey not found");
  }

  private async consumeChallenge(challengeId: unknown, type: "register" | "login") {
    if (typeof challengeId !== "string" || !challengeId) {
      throw new HttpError(400, "challengeId is required");
    }
    // single use
    const stored = await this.repo.challenges.consume(challengeId, type);
    if (!stored || stored.expiresAt <= new Date()) {
      throw new HttpError(400, "Challenge expired or not found");
    }
    return stored;
  }
}
