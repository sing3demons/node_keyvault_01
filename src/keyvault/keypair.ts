import crypto from "node:crypto";

export interface RsaKeyPairOptions {
    /** RSA modulus size in bits (default 2048) */
    modulusLength?: 2048 | 3072 | 4096;
    /** JWS algorithm advertised in the JWK (default RS256) */
    alg?: "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512";
    /** days until the key expires (default 365) */
    validDays?: number;
}

export interface RsaKeyPair {
    kid: string;
    /** private JWK as a JSON string, including kid/use/alg */
    privateValue: string;
    /** public JWKS ({ keys: [jwk] }) as a JSON string, ready to serve from /.well-known/jwks.json */
    publicValue: string;
    expiresOn: Date;
}

/** Generates an RSA signing key pair and exports both halves as JWK. */
export function generateRsaKeyPair(options: RsaKeyPairOptions = {}): RsaKeyPair {
    const { modulusLength = 2048, alg = "RS256", validDays = 365 } = options;

    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength });
    const privJwk = privateKey.export({ format: "jwk" });
    const pubJwk = publicKey.export({ format: "jwk" });
    if (!pubJwk.n || privJwk.n !== pubJwk.n) {
        throw new Error("public key does not match private key");
    }

    const kid = crypto.createHash("sha256").update(pubJwk.n).digest("base64url").slice(0, 32);
    const meta = { kid, use: "sig", alg };

    return {
        kid,
        privateValue: JSON.stringify({ ...privJwk, ...meta }),
        publicValue: JSON.stringify({ keys: [{ ...pubJwk, ...meta }] }),
        expiresOn: new Date(Date.now() + validDays * 24 * 3600 * 1000)
    };
}
