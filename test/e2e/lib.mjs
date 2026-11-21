// Shared helpers for the E2E scripts: a cookie-keeping "browser", PKCE authorize, Mailpit readers.
import { createHash, randomBytes } from "node:crypto";
export const BASE = process.env.BASE ?? "http://localhost:3999";
const MAIL = "http://localhost:8025";
export const UI_REDIRECT = "http://localhost:3001/callback";
let failures = 0;
export const ok = (c, m) => { console.log(`${c ? "PASS" : "FAIL"}  ${m}`); if (!c) failures++; };
export const done = () => { console.log(failures ? `\n${failures} FAILED` : "\nall passed"); process.exit(failures ? 1 : 0); };
export const b64 = (b) => b.toString("base64url");
export const rand = () => randomBytes(3).toString("hex");
export const claims = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url"));

export class Browser {
  constructor(ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36") { this.ua = ua; this.jar = new Map(); }
  get cookieHeader() { return [...this.jar].map(([k, v]) => `${k}=${v}`).join("; "); }
  has(name) { return this.jar.has(name); }
  async fetch(path, init = {}) {
    const headers = new Headers(init.headers);
    headers.set("user-agent", this.ua);
    if (this.jar.size) headers.set("cookie", this.cookieHeader);
    const res = await fetch(path.startsWith("http") ? path : BASE + path, { ...init, headers, redirect: "manual" });
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(";");
      const [k, v] = pair.split("=");
      if (attrs.some((a) => /max-age=0/i.test(a.trim())) || v === "") this.jar.delete(k); else this.jar.set(k, v);
    }
    return res;
  }
  async post(path, body, headers = {}) {
    const res = await this.fetch(path, { method: "POST", headers: { "content-type": "application/json", origin: "http://localhost:3001", ...headers }, body: JSON.stringify(body) });
    return { s: res.status, b: await res.json().catch(() => null), h: res.headers };
  }
  async json(path, token, init = {}) {
    const res = await this.fetch(path, { ...init, headers: { ...(init.body ? { "content-type": "application/json" } : {}), authorization: `Bearer ${token}`, ...(init.headers ?? {}) } });
    return { s: res.status, b: res.status === 204 ? null : await res.json().catch(() => null), h: res.headers };
  }
  /** GET /oauth/authorize with a fresh PKCE pair; returns request_id (or the error redirect). */
  async authorize({ clientId = "keyvault-web", redirectUri = UI_REDIRECT, scope = "openid email profile secrets", state = "st-" + rand() } = {}) {
    const verifier = b64(randomBytes(48));
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirectUri, state, code_challenge: b64(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256", nonce: "n" });
    if (scope !== null) q.set("scope", scope);
    const res = await this.fetch(`/oauth/authorize?${q}`);
    const loc = res.headers.get("location");
    const url = loc ? new URL(loc, BASE) : null;
    return { status: res.status, rid: url?.searchParams.get("request_id") ?? null, location: url, verifier, state, redirectUri, body: loc ? null : await res.json().catch(() => null) };
  }
}

/** POST /oauth/token. auth: { basic: [id, secret] } | { post: [id, secret] } | { none: id } */
export async function token(form, auth) {
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  const body = new URLSearchParams(form);
  if (auth.basic) headers.authorization = "Basic " + Buffer.from(`${encodeURIComponent(auth.basic[0])}:${encodeURIComponent(auth.basic[1])}`).toString("base64");
  if (auth.post) { body.set("client_id", auth.post[0]); body.set("client_secret", auth.post[1]); }
  if (auth.none) body.set("client_id", auth.none);
  const res = await fetch(`${BASE}/oauth/token`, { method: "POST", headers, body });
  return { s: res.status, b: await res.json().catch(() => null), h: res.headers };
}
export const exchange = (redirect, a, auth) => token({ grant_type: "authorization_code", code: new URL(redirect).searchParams.get("code"), redirect_uri: a.redirectUri, code_verifier: a.verifier }, auth);
export async function revoke(tok, auth) {
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  const body = new URLSearchParams(tok ? { token: tok } : {});
  if (auth.basic) headers.authorization = "Basic " + Buffer.from(`${auth.basic[0]}:${auth.basic[1]}`).toString("base64");
  if (auth.none) body.set("client_id", auth.none);
  const res = await fetch(`${BASE}/oauth/revoke`, { method: "POST", headers, body });
  return { s: res.status, h: res.headers };
}

// mail already in Mailpit when this script starts belongs to earlier runs (IDs, not clocks: Docker's may drift)
const seen = new Set(((await (await fetch(`${MAIL}/api/v1/messages?limit=5000`)).json()).messages ?? []).map((m) => m.ID));
/** Next unseen email to `to`: { code?, link?, subject }. */
export async function nextMail(to) {
  for (let i = 0; i < 40; i++) {
    const l = await (await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent("to:" + to)}`)).json();
    for (const m of (l.messages ?? []).slice().reverse()) {
      if (seen.has(m.ID)) continue;
      seen.add(m.ID);
      const full = await (await fetch(`${MAIL}/api/v1/message/${m.ID}`)).json();
      const code = /code is: (\d{6})/.exec(full.Text)?.[1];
      const url = /(http\S+\/verify-email\?\S+)/.exec(full.Text)?.[1];
      const link = url ? new URL(url) : null;
      return { code, link, id: link?.searchParams.get("id"), token: link?.searchParams.get("token"), subject: full.Subject };
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("no email for " + to);
}

/** Registers on the login page and finishes with the emailed code; returns { user, tokens } (keyvault-web, code mode). */
export async function registerWithCode(b, name) {
  const a = await b.authorize();
  const email = `${name}@example.com`;
  const r = await b.post("/auth/register", { request_id: a.rid, username: name, email, password: "password123", profiles: [{ lang: "en", firstName: "T", lastName: "U" }] });
  const m = await nextMail(email);
  const v = await b.post("/auth/email/verify", { request_id: a.rid, challengeId: r.b.verification.challengeId, code: m.code });
  const t = await exchange(v.b.redirect, a, { none: "keyvault-web" });
  return { email, password: "password123", tokens: t.b };
}

/** Full master sign-in (password -> emailed OTP -> session). Returns "Bearer <token>". */
export async function masterBearer(id = "master", password = "correct-horse-battery-staple") {
  const b = new Browser();
  const r = await b.post("/auth/master/login", { username: id, password });
  if (r.s !== 200) throw new Error(`master login: ${r.s} ${r.b?.error_description}`);
  const m = await nextMail("master@example.com");
  const v = await b.post("/auth/master/verify", { challengeId: r.b.verify.challengeId, code: m.code });
  if (v.s !== 200) throw new Error(`master verify: ${v.s} ${v.b?.error_description}`);
  return `Bearer ${v.b.access_token}`;
}
