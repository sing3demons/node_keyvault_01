// Email verification with codes (OTP) + device tracking. Server: built-in client in code mode.
import { createHash, randomBytes } from "node:crypto";
const BASE = process.env.BASE ?? "http://localhost:3999";
const MAIL = "http://localhost:8025";
const REDIRECT = "http://localhost:3001/callback";
let failures = 0;
const ok = (cond, msg) => { console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`); if (!cond) failures++; };
const b64 = (b) => b.toString("base64url");

class Browser {
  constructor(ua) { this.ua = ua; this.cookie = ""; }
  async fetch(path, init = {}) {
    const headers = new Headers(init.headers);
    headers.set("user-agent", this.ua);
    if (this.cookie) headers.set("cookie", this.cookie);
    const res = await fetch(BASE + path, { ...init, headers, redirect: "manual" });
    const set = res.headers.getSetCookie?.() ?? [];
    for (const c of set) if (c.startsWith("kv_device=")) this.cookie = c.split(";")[0];
    return res;
  }
  async json(path, body, token) {
    const res = await this.fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body)
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  }
  async authorize() {
    this.verifier = b64(randomBytes(48));
    const challenge = b64(createHash("sha256").update(this.verifier).digest());
    const q = new URLSearchParams({ response_type: "code", client_id: "keyvault-web", redirect_uri: REDIRECT, scope: "openid email profile secrets", state: "s", code_challenge: challenge, code_challenge_method: "S256", nonce: "n" });
    const res = await this.fetch(`/oauth/authorize?${q}`);
    return new URL(res.headers.get("location"), BASE).searchParams.get("request_id");
  }
  async exchange(redirect) {
    const code = new URL(redirect).searchParams.get("code");
    const res = await this.fetch("/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: "keyvault-web", code_verifier: this.verifier }) });
    return res.json();
  }
}

async function latestCode(to) {
  for (let i = 0; i < 30; i++) {
    const list = await (await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent("to:" + to)}`)).json();
    const msg = list.messages?.[0];
    if (msg) {
      const full = await (await fetch(`${MAIL}/api/v1/message/${msg.ID}`)).json();
      const m = /code is: (\d{6})/.exec(full.Text);
      if (m && m[1] !== latestCode.last?.[to]) { (latestCode.last ??= {})[to] = m[1]; return { code: m[1], subject: full.Subject }; }
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("no email for " + to);
}
const claims = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());

const id = randomBytes(3).toString("hex");
const username = `e2e_${id}`, email = `e2e_${id}@example.com`, password = "correct horse battery";
const mac = new Browser("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
const phone = new Browser("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");

// 1. register -> code by email -> verify -> signed in
let rid = await mac.authorize();
let r = await mac.json("/auth/register", { request_id: rid, username, email, password, profiles: [{ lang: "en", firstName: "E", lastName: "Two" }] });
ok(r.status === 201 && r.body.verification?.challengeId && r.body.emailVerified === false, `register 201, unverified, verification pending (${r.body?.verification?.email})`);
const reg = r.body.verification;
let mail = await latestCode(email);
ok(/verification code/.test(mail.subject), `verification email received: "${mail.subject}"`);
r = await mac.json("/auth/email/resend", { challengeId: reg.challengeId });
ok(r.status === 429, `resend inside cooldown -> 429 (${r.body?.error_description})`);
r = await mac.json("/auth/email/verify", { request_id: rid, challengeId: reg.challengeId, code: mail.code === "000000" ? "111111" : "000000" });
ok(r.status === 400 && /4 attempts left/.test(r.body.error_description), `wrong code -> 400 "${r.body?.error_description}"`);
r = await mac.json("/auth/email/verify", { challengeId: reg.challengeId, code: mail.code });
ok(r.status === 400, "sign-in code without its request_id is rejected");
r = await mac.json("/auth/email/verify", { request_id: rid, challengeId: reg.challengeId, code: mail.code });
ok(r.status === 200 && r.body.redirect, "correct code -> signed in (redirect)");
ok(mac.cookie.startsWith("kv_device="), "device cookie set");
let t = await mac.exchange(r.body.redirect);
ok(claims(t.id_token).email_verified === true, "ID Token email_verified = true");
r = await mac.json("/auth/email/verify", { request_id: rid, challengeId: reg.challengeId, code: mail.code });
ok(r.status === 400, "code cannot be reused");
let me = await (await mac.fetch("/auth/me", { headers: { authorization: `Bearer ${t.access_token}` } })).json();
ok(me.emailVerified === true, "/auth/me emailVerified = true");

// 2. username + password on a verified account -> no code
rid = await mac.authorize();
r = await mac.json("/auth/login/password", { request_id: rid, username, password });
ok(r.status === 200 && r.body.redirect, "username login -> straight in");
const macTokens = await mac.exchange(r.body.redirect);

// 3. email + password -> code required
rid = await phone.authorize();
r = await phone.json("/auth/login/password", { request_id: rid, username: email.toUpperCase(), password });
ok(r.status === 200 && r.body.verify?.reason === "login", `email login -> code step (${r.body?.verify?.email})`);
r2 = null;
var r2;
r2 = await phone.json("/auth/login/password", { request_id: rid, username: email, password: "wrong password" });
ok(r2.status === 401, "email login with wrong password -> 401 (no email sent)");
mail = await latestCode(email);
ok(/sign-in code/.test(mail.subject), `sign-in email received: "${mail.subject}"`);
r = await phone.json("/auth/email/verify", { request_id: rid, challengeId: r.body.verify.challengeId, code: mail.code });
ok(r.status === 200 && r.body.redirect, "email login + code -> signed in");
const phoneTokens = await phone.exchange(r.body.redirect);

// 4. devices
let devs = (await (await mac.fetch("/auth/me/devices", { headers: { authorization: `Bearer ${macTokens.access_token}` } })).json()).devices;
ok(devs.length === 2, `2 devices listed: ${devs.map((d) => `${d.name}${d.current ? " (current)" : ""} x${d.signIns} ${d.lastMethod} active=${d.active}`).join(", ")}`);
const macDev = devs.find((d) => d.current), phoneDev = devs.find((d) => !d.current);
ok(macDev?.name === "Chrome on macOS" && macDev.signIns === 2 && macDev.lastMethod === "password", "mac device: same device reused across sign-ins");
ok(phoneDev?.name === "Safari on iPhone" && phoneDev.lastMethod === "password+email_code" && phoneDev.active, "phone device recorded with method password+email_code");
r = await mac.fetch(`/auth/me/devices/${macDev.id}`, { method: "DELETE", headers: { authorization: `Bearer ${macTokens.access_token}` } });
ok(r.status === 409, "removing the current device -> 409");
r = await mac.fetch(`/auth/me/devices/${phoneDev.id}/sign-out`, { method: "POST", headers: { authorization: `Bearer ${macTokens.access_token}` } });
ok(r.status === 204, "sign out phone -> 204");
r = await phone.fetch("/auth/me", { headers: { authorization: `Bearer ${phoneTokens.access_token}` } });
ok(r.status === 401, "phone access token no longer works");
r = await phone.fetch("/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: phoneTokens.refresh_token, client_id: "keyvault-web" }) });
ok(r.status === 400, "phone refresh token revoked");
r = await mac.fetch("/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: macTokens.refresh_token, client_id: "keyvault-web" }) });
const refreshed = await r.json();
ok(r.status === 200, "mac refresh still works");
devs = (await (await mac.fetch("/auth/me/devices", { headers: { authorization: `Bearer ${refreshed.access_token}` } })).json()).devices;
ok(devs.find((d) => d.id === phoneDev.id)?.active === false && devs.find((d) => d.current)?.id === macDev.id, "phone shows signed out; refreshed token still marks mac as current");
r = await mac.fetch(`/auth/me/devices/${phoneDev.id}`, { method: "DELETE", headers: { authorization: `Bearer ${refreshed.access_token}` } });
ok(r.status === 204, "remove phone -> 204");
devs = (await (await mac.fetch("/auth/me/devices", { headers: { authorization: `Bearer ${refreshed.access_token}` } })).json()).devices;
ok(devs.length === 1, "1 device left");

// 5. changing email -> unverified; account-page verification
r = await mac.fetch("/auth/me", { method: "PATCH", headers: { "content-type": "application/json", authorization: `Bearer ${refreshed.access_token}` }, body: JSON.stringify({ email: `new_${email}` }) });
me = await r.json();
ok(me.emailVerified === false, "email changed -> unverified");
r = await mac.json("/auth/me/email/verification", {}, refreshed.access_token);
ok(r.status === 200 && r.body.reason === "verify_email", "account page: code sent");
mail = await latestCode(`new_${email}`);
r = await mac.json("/auth/email/verify", { challengeId: r.body.challengeId, code: mail.code });
ok(r.status === 200 && r.body.verified === true, "account page: code verifies address");
me = await (await mac.fetch("/auth/me", { headers: { authorization: `Bearer ${refreshed.access_token}` } })).json();
ok(me.emailVerified === true, "new email verified");

// 6. too many wrong codes
rid = await mac.authorize();
r = await mac.json("/auth/login/password", { request_id: rid, username: `new_${email}`, password });
const ch = r.body.verify.challengeId;
let last;
for (let i = 0; i < 5; i++) last = await mac.json("/auth/email/verify", { request_id: rid, challengeId: ch, code: "999999" });
ok(/Too many wrong codes/.test(last.body.error_description), `5 wrong codes -> "${last.body.error_description}"`);
r = await mac.json("/auth/email/verify", { request_id: rid, challengeId: ch, code: (await latestCode(`new_${email}`)).code });
ok(r.status === 400, "challenge is gone after too many attempts");

console.log(failures ? `\n${failures} FAILED` : "\nall passed");
process.exit(failures ? 1 : 0);
