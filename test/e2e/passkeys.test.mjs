// Passkey management: register (with a software authenticator), list, rename, sign in with it, remove.
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { b64, Browser, done, exchange, ok, rand, registerWithCode } from "./lib.mjs";

const ORIGIN = "http://localhost:3001";
const RP_ID = "localhost";
const sha256 = (b) => createHash("sha256").update(b).digest();

// ------------------------------------------------------------------ minimal CBOR (what attestation "none" needs)
const head = (major, n) => {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
};
const cbor = (v) => {
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") { const s = Buffer.from(v, "utf8"); return Buffer.concat([head(3, s.length), s]); }
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error("cbor: unsupported " + typeof v);
};

/** A platform authenticator holding one ES256 passkey. */
class SoftAuthenticator {
  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.privateKey = privateKey;
    this.jwk = publicKey.export({ format: "jwk" });
    this.credId = randomBytes(32);
    this.counter = 0;
  }
  create(publicKey) {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: publicKey.challenge, origin: ORIGIN }));
    const coseKey = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(this.jwk.x, "base64url")], [-3, Buffer.from(this.jwk.y, "base64url")]]));
    const idLen = Buffer.alloc(2); idLen.writeUInt16BE(this.credId.length);
    const authData = Buffer.concat([sha256(RP_ID), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), idLen, this.credId, coseKey]);
    this.userHandle = publicKey.user.id;
    return {
      id: b64(this.credId), rawId: b64(this.credId), type: "public-key", transports: ["internal"],
      response: { clientDataJSON: b64(clientDataJSON), attestationObject: b64(cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]))) }
    };
  }
  get(publicKey) {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: publicKey.challenge, origin: ORIGIN }));
    const counter = Buffer.alloc(4); counter.writeUInt32BE(++this.counter);
    const authData = Buffer.concat([sha256(RP_ID), Buffer.from([0x05]), counter]);
    const signature = sign("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), this.privateKey);
    return {
      id: b64(this.credId), rawId: b64(this.credId), type: "public-key",
      response: { clientDataJSON: b64(clientDataJSON), authenticatorData: b64(authData), signature: b64(signature), userHandle: this.userHandle }
    };
  }
}

async function addPasskey(b, at, auth, name) {
  const o = await b.json("/auth/webauthn/register/options", at, { method: "POST", body: "{}" });
  return b.json("/auth/webauthn/register/verify", at, { method: "POST", body: JSON.stringify({ challengeId: o.b.challengeId, name, credential: auth.create(o.b.publicKey) }) });
}
const list = async (b, at) => (await b.json("/auth/webauthn/credentials", at)).b?.passkeys;
const rename = (b, at, id, name) => b.json(`/auth/webauthn/credentials/${id}`, at, { method: "PATCH", body: JSON.stringify({ name }) });
const remove = (b, at, id) => b.json(`/auth/webauthn/credentials/${id}`, at, { method: "DELETE" });

// ------------------------------------------------------------------ setup
const alice = new Browser();
const { tokens: at1 } = await registerWithCode(alice, `pk_a_${rand()}`);
const A = at1.access_token;
const bob = new Browser();
const { tokens: bt } = await registerWithCode(bob, `pk_b_${rand()}`);
const B = bt.access_token;

ok(Array.isArray(await list(alice, A)) && (await list(alice, A)).length === 0, "new account has no passkeys");

// ------------------------------------------------------------------ add
const laptop = new SoftAuthenticator();
const r1 = await addPasskey(alice, A, laptop, "Laptop");
ok(r1.s === 201 && r1.b.name === "Laptop", `register passkey -> 201 (${r1.s} ${r1.b?.error_description ?? ""})`);
const phone = new SoftAuthenticator();
const r2 = await addPasskey(alice, A, phone, undefined);
ok(r2.s === 201 && r2.b.name === "Passkey", "register without a name -> default name");
const dup = await addPasskey(alice, A, laptop, "Again");
ok(dup.s === 409, `same authenticator twice -> 409 (${dup.s})`);

let pks = await list(alice, A);
ok(pks.length === 2 && pks.every((p) => p.createdAt && !p.lastUsedAt), "list shows both, never used");
ok((await list(bob, B)).length === 0, "other user sees none of them");

// ------------------------------------------------------------------ rename
const rn = await rename(alice, A, r2.b.id, "  Phone  ");
ok(rn.s === 200 && rn.b.name === "Phone" && rn.b.id === r2.b.id, `rename -> 200, trimmed (${rn.s} ${rn.b?.name})`);
ok((await list(alice, A)).find((p) => p.id === r2.b.id)?.name === "Phone", "rename persisted");
ok((await rename(alice, A, r2.b.id, "   ")).s === 400, "empty name -> 400");
ok((await rename(alice, A, r2.b.id, "x".repeat(65))).s === 400, "name over 64 chars -> 400");
ok((await rename(bob, B, r2.b.id, "mine now")).s === 404, "renaming someone else's passkey -> 404");
ok((await rename(alice, A, "00000000-0000-4000-8000-000000000000", "x")).s === 404, "unknown id -> 404");
ok((await rename(alice, A, "not-a-uuid", "x")).s === 404, "malformed id -> 404");
const pwId = "password"; // the password credential's id is never exposed; any non-passkey id must 404
ok((await rename(alice, A, pwId, "x")).s === 404, "non-passkey id -> 404");
ok((await alice.fetch(`/auth/webauthn/credentials/${r2.b.id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: '{"name":"x"}' })).status === 401, "rename without a token -> 401");

// ------------------------------------------------------------------ the renamed passkey still signs in
const a = await alice.authorize();
const lo = await alice.post("/auth/webauthn/login/options", { request_id: a.rid });
const lv = await alice.post("/auth/webauthn/login/verify", { request_id: a.rid, challengeId: lo.b.challengeId, credential: phone.get(lo.b.publicKey) });
ok(lv.s === 200 && lv.b.redirect, `sign in with the renamed passkey (${lv.s} ${lv.b?.error_description ?? ""})`);
const t = await exchange(lv.b.redirect, a, { none: "keyvault-web" });
ok(t.s === 200, "code exchange after passkey sign-in");
pks = await list(alice, A);
ok(pks.find((p) => p.id === r2.b.id)?.lastUsedAt && !pks.find((p) => p.id === r1.b.id)?.lastUsedAt, "lastUsedAt set only on the one used");

// ------------------------------------------------------------------ remove
ok((await remove(bob, B, r1.b.id)).s === 404, "removing someone else's passkey -> 404");
const del = await remove(alice, A, r1.b.id);
ok(del.s === 204, `remove -> 204 (${del.s})`);
pks = await list(alice, A);
ok(pks.length === 1 && pks[0].id === r2.b.id, "removed passkey is gone from the list");
ok((await remove(alice, A, r1.b.id)).s === 404, "removing it again -> 404");
ok((await rename(alice, A, r1.b.id, "ghost")).s === 404, "renaming a removed passkey -> 404");

const a2 = await alice.authorize();
const lo2 = await alice.post("/auth/webauthn/login/options", { request_id: a2.rid });
const lv2 = await alice.post("/auth/webauthn/login/verify", { request_id: a2.rid, challengeId: lo2.b.challengeId, credential: laptop.get(lo2.b.publicKey) });
ok(lv2.s === 401, `removed passkey can no longer sign in (${lv2.s})`);

const back = await addPasskey(alice, A, laptop, "Laptop again");
ok(back.s === 201, "a removed authenticator can be registered again");

done();
