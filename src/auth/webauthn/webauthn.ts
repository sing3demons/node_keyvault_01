import { Fido2Lib } from "fido2-lib";
import { randomUUID } from "node:crypto";
import { fromBase64Url, randomToken, toBase64Url } from "../shared/crypto.js";
import { HttpError } from "../shared/http.js";
import { errorMessage, expiresIn } from "../shared/util.js";
import { isWebAuthn, type WebAuthnCredential } from "./model.js";
import { DuplicateKeyError, type AuthRepository } from "./repository.js";
import type { AssertionCredential, AttestationCredential } from "./schemas.js";

export interface WebAuthnSettings {
  rpId: string;
  rpName: string;
  origins: string[];
}

const CHALLENGE_TTL_MS = 5 * 60_000;

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
    const existing = await this.passkeysOf(userId);
    const options = await this.fido.attestationOptions();
    const challenge = toBase64Url(options.challenge);
    const challengeId = randomToken(16);
    await this.repo.challenges.create({
      id: challengeId,
      type: "register",
      challenge,
      userId,
      expiresAt: expiresIn(CHALLENGE_TTL_MS)
    });
    return {
      challengeId,
      publicKey: {
        rp: options.rp,
        user: { id: this.userHandleOf(userId), name: username, displayName: username },
        challenge,
        pubKeyCredParams: options.pubKeyCredParams,
        timeout: options.timeout,
        attestation: options.attestation,
        authenticatorSelection: { ...options.authenticatorSelection, residentKey: "required" },
        excludeCredentials: existing.map(({ webauthn: w }) => ({ type: "public-key", id: w.credId, transports: w.transports }))
      }
    };
  }

  async verifyRegistration(userId: string, challengeId: string, credential: AttestationCredential, name?: string) {
    const stored = await this.consumeChallenge(challengeId, "register");
    if (stored.userId !== userId) {
      throw new HttpError(400, "Challenge does not belong to this user");
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
      throw new HttpError(400, `Passkey registration failed: ${errorMessage(error)}`);
    }
    const attested = this.attestedCredential(result.authnrData);
    const doc: WebAuthnCredential = {
      id: randomUUID(),
      type: "webauthn",
      webauthn: {
        ...attested,
        transports: credential.transports,
        name: name || "Passkey"
      },
      createdAt: new Date()
    };
    try {
      await this.repo.users.addCredential(userId, doc);
    } catch (error) {
      if (error instanceof DuplicateKeyError) throw new HttpError(409, "Passkey already registered");
      throw error;
    }
    return { id: doc.id, name: doc.webauthn.name, createdAt: doc.createdAt.toISOString() };
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
      expiresAt: expiresIn(CHALLENGE_TTL_MS)
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
  async verifyLogin(challengeId: string, authRequestId: string, credential: AssertionCredential): Promise<string> {
    const stored = await this.consumeChallenge(challengeId, "login");
    if (stored.authRequestId !== authRequestId) {
      throw new HttpError(400, "Challenge does not belong to this authorization request");
    }
    const r = credential.response;
    const found = await this.repo.users.findByWebAuthnCredId(credential.rawId);
    if (!found) {
      throw new HttpError(401, "Unknown passkey", "access_denied");
    }
    const { user, credential: cred } = found;
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
          publicKey: cred.webauthn.publicKeyPem,
          prevCounter: cred.webauthn.counter,
          userHandle: this.userHandleOf(user.id)
        }
      );
    } catch (error) {
      throw new HttpError(401, `Passkey verification failed: ${errorMessage(error)}`, "access_denied");
    }
    await this.repo.users.recordWebAuthnUse(
      user.id,
      cred.id,
      this.signCounter(result.authnrData, cred.webauthn.counter),
      new Date()
    );
    return user.id;
  }

  // ---------------------------------------------------------------- management

  async list(userId: string) {
    const creds = await this.passkeysOf(userId);
    return creds.map((c) => ({
      id: c.id,
      name: c.webauthn.name,
      createdAt: c.createdAt.toISOString(),
      lastUsedAt: c.lastUsedAt?.toISOString()
    }));
  }

  async remove(userId: string, id: string): Promise<void> {
    // only passkeys can be removed through this endpoint
    if (!(await this.passkeysOf(userId)).some((c) => c.id === id)) {
      throw new HttpError(404, "Passkey not found");
    }
    const result = await this.repo.users.removeCredential(userId, id);
    if (result === "not_found") throw new HttpError(404, "Passkey not found");
    if (result === "last_credential") throw new HttpError(409, "Cannot remove your only way to sign in");
  }

  private async passkeysOf(userId: string): Promise<WebAuthnCredential[]> {
    const user = await this.repo.users.findById(userId);
    return user?.credentials.filter(isWebAuthn) ?? [];
  }

  private async consumeChallenge(challengeId: string, type: "register" | "login") {
    // single use
    const stored = await this.repo.challenges.consume(challengeId, type);
    if (!stored || stored.expiresAt <= new Date()) {
      throw new HttpError(400, "Challenge expired or not found");
    }
    return stored;
  }

  // ---------------------------------------------------------------- fido2-lib adapters

  /** WebAuthn user.id / userHandle = UTF-8 bytes of the user's id. */
  private userHandleOf(userId: string): string {
    return Buffer.from(userId, "utf8").toString("base64url");
  }

  /** fido2-lib types authnrData as Map<string, any>; read the fields we need with runtime checks. */
  private attestedCredential(authnrData: Map<string, unknown>) {
    const credId = authnrData.get("credId");
    const publicKeyPem = authnrData.get("credentialPublicKeyPem");
    const counter = authnrData.get("counter");
    if (!(credId instanceof ArrayBuffer) || typeof publicKeyPem !== "string" || typeof counter !== "number") {
      throw new HttpError(400, "Passkey registration failed: authenticator data is incomplete");
    }
    return { credId: toBase64Url(credId), publicKeyPem, counter };
  }

  private signCounter(authnrData: Map<string, unknown>, fallback: number): number {
    const counter = authnrData.get("counter");
    return typeof counter === "number" ? counter : fallback;
  }
}
