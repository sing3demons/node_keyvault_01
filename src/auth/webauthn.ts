import { Fido2Lib } from "fido2-lib";
import { ObjectId } from "mongodb";
import { fromBase64Url, randomToken, toBase64Url } from "./crypto.js";
import { HttpError } from "./errors.js";
import type { AuthStore, WebAuthnCredentialDoc } from "./store.js";

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

const CHALLENGE_TTL_MS = 5 * 60_000;
const later = (ms: number) => new Date(Date.now() + ms);
/** WebAuthn user.id / userHandle = UTF-8 bytes of the user's ObjectId hex string. */
const userHandleOf = (userId: ObjectId) => Buffer.from(userId.toHexString(), "utf8").toString("base64url");

export class WebAuthnService {
  private readonly fido: Fido2Lib;

  constructor(
    private readonly store: AuthStore,
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
    const uid = new ObjectId(userId);
    const existing = await this.store.credentials.find({ userId: uid }).toArray();
    const options = await this.fido.attestationOptions();
    const challenge = toBase64Url(options.challenge);
    const challengeId = randomToken(16);
    await this.store.challenges.insertOne({
      _id: challengeId,
      type: "register",
      challenge,
      userId: uid,
      expiresAt: later(CHALLENGE_TTL_MS)
    });
    return {
      challengeId,
      publicKey: {
        rp: options.rp,
        user: { id: userHandleOf(uid), name: username, displayName: username },
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
    const uid = new ObjectId(userId);
    const stored = await this.consumeChallenge(challengeId, "register");
    if (!stored.userId?.equals(uid)) {
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
    const doc: WebAuthnCredentialDoc = {
      _id: new ObjectId(),
      userId: uid,
      credId: toBase64Url(result.authnrData.get("credId") as ArrayBuffer),
      publicKeyPem: result.authnrData.get("credentialPublicKeyPem") as string,
      counter: Number(result.authnrData.get("counter") ?? 0),
      transports: credential.transports,
      name: typeof name === "string" && name.trim() ? name.trim().slice(0, 64) : "Passkey",
      createdAt: new Date()
    };
    try {
      await this.store.credentials.insertOne(doc);
    } catch (error) {
      if ((error as { code?: number }).code === 11000) throw new HttpError(409, "Passkey already registered");
      throw error;
    }
    return { id: doc._id.toHexString(), name: doc.name, createdAt: doc.createdAt.toISOString() };
  }

  // ---------------------------------------------------------------- authentication (during /oauth/authorize)

  async loginOptions(authRequestId: string) {
    const options = await this.fido.assertionOptions();
    const challenge = toBase64Url(options.challenge);
    const challengeId = randomToken(16);
    await this.store.challenges.insertOne({
      _id: challengeId,
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
  async verifyLogin(challengeId: unknown, authRequestId: string, credential: CredentialJSON): Promise<ObjectId> {
    const stored = await this.consumeChallenge(challengeId, "login");
    if (stored.authRequestId !== authRequestId) {
      throw new HttpError(400, "Challenge does not belong to this authorization request");
    }
    const r = credential?.response;
    if (!credential?.rawId || !r?.clientDataJSON || !r.authenticatorData || !r.signature) {
      throw new HttpError(400, "Malformed credential");
    }
    const cred = await this.store.credentials.findOne({ credId: credential.rawId });
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
    await this.store.credentials.updateOne(
      { _id: cred._id },
      { $set: { counter: Number(result.authnrData.get("counter") ?? cred.counter), lastUsedAt: new Date() } }
    );
    return cred.userId;
  }

  // ---------------------------------------------------------------- management

  async list(userId: string) {
    const creds = await this.store.credentials.find({ userId: new ObjectId(userId) }).sort({ createdAt: 1 }).toArray();
    return creds.map((c) => ({
      id: c._id.toHexString(),
      name: c.name,
      createdAt: c.createdAt.toISOString(),
      lastUsedAt: c.lastUsedAt?.toISOString()
    }));
  }

  async remove(userId: string, id: string): Promise<void> {
    if (!ObjectId.isValid(id)) throw new HttpError(404, "Passkey not found");
    const res = await this.store.credentials.deleteOne({ _id: new ObjectId(id), userId: new ObjectId(userId) });
    if (res.deletedCount === 0) throw new HttpError(404, "Passkey not found");
  }

  private async consumeChallenge(challengeId: unknown, type: "register" | "login") {
    if (typeof challengeId !== "string" || !challengeId) {
      throw new HttpError(400, "challengeId is required");
    }
    // single use
    const stored = await this.store.challenges.findOneAndDelete({ _id: challengeId, type });
    if (!stored || stored.expiresAt <= new Date()) {
      throw new HttpError(400, "Challenge expired or not found");
    }
    return stored;
  }
}
