// Built-in client seeded with email_verification=link (fresh DB, EMAIL_VERIFICATION=link on first start).
import { Browser, claims, done, exchange, nextMail, ok, rand } from "./lib.mjs";
const id = rand(), email = `lk_${id}@example.com`, password = "password123";
const tabA = new Browser();

// register on the login page (tab A) -> link -> opened in tab B: continue -> fresh sign-in -> resume
let a = await tabA.authorize();
let r = await tabA.post("/auth/register", { request_id: a.rid, username: `lk_${id}`, email, password, profiles: [{ lang: "en", firstName: "L", lastName: "K" }] });
ok(r.s === 201 && r.b.verification.method === "link", "register -> verification.method = link (seeded client setting)");
let m = await nextMail(email);
ok(m.id === r.b.verification.challengeId && m.link.searchParams.get("signin") === "1", `link: ${m.link.origin}/verify-email?…&signin=1 ("${m.subject}")`);
const tabB = new Browser("Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/133.0");
r = await tabB.post("/auth/email/link", { challengeId: m.id, token: "x".repeat(43) });
ok(r.s === 400, "forged token rejected");
r = await tabB.post("/auth/email/link", { challengeId: m.id, token: m.token });
ok(r.b.continue?.startsWith("http://localhost:3001/?iss="), `continue -> ${r.b.continue}`);
const b = await tabB.authorize(); // the UI at initiate_login_uri starts a sign-in
r = await tabB.post("/auth/email/link/resume", { request_id: b.rid });
ok(!!r.b.redirect, "login page resumes the link -> redirect");
let t = await exchange(r.b.redirect, b, { none: "keyvault-web" });
ok(t.s === 200 && claims(t.b.id_token).email_verified, "tab B gets tokens with its own PKCE verifier");
r = await tabB.post("/auth/email/link/resume", { request_id: (await tabB.authorize()).rid });
ok(r.s === 400, "resume is single use");
const devs = (await tabB.json("/auth/me/devices", t.b.access_token)).b.devices;
ok(devs[0]?.name === "Firefox on Windows" && devs[0].lastMethod === "registration", `device = the browser that opened the link (${devs[0]?.name}, ${devs[0]?.lastMethod})`);

// email login -> link; resend replaces it
a = await tabA.authorize();
r = await tabA.post("/auth/login/password", { request_id: a.rid, username: email, password });
ok(r.b.verify?.method === "link" && r.b.verify.reason === "login", "email login -> link step");
const ch = r.b.verify.challengeId;
const first = await nextMail(email);
await tabA.post("/auth/email/resend", { challengeId: ch });
const second = await nextMail(email);
r = await tabB.post("/auth/email/link", { challengeId: ch, token: first.token });
ok(r.s === 400, "old link dead after resend");
r = await tabB.post("/auth/email/link", { challengeId: ch, token: second.token });
const c = await tabB.authorize();
r = await tabB.post("/auth/email/link/resume", { request_id: c.rid });
t = await exchange(r.b.redirect, c, { none: "keyvault-web" });
ok(t.s === 200, "new link signs in");
ok((await tabB.json("/auth/me/devices", t.b.access_token)).b.devices.some((d) => d.lastMethod === "password+email_link"), "method password+email_link");

// account page: verify-only link (no sign-in, polled)
await tabB.json("/auth/me", t.b.access_token, { method: "PATCH", body: JSON.stringify({ email: `new_${email}` }) });
r = await tabB.post("/auth/me/email/verification", {}, { authorization: `Bearer ${t.b.access_token}` });
ok(r.b.method === "link", "account verification uses the token's client setting (link)");
const ch3 = r.b.challengeId;
const l3 = await nextMail(`new_${email}`);
ok(l3.link.searchParams.get("signin") === null, "verify link has no signin=1");
ok((await tabB.post("/auth/email/status", { challengeId: ch3 })).b.pending === true, "poll: pending");
r = await new Browser().post("/auth/email/link", { challengeId: ch3, token: l3.token });
ok(r.b.verified === true, "verify link -> verified (no tokens)");
ok((await tabB.post("/auth/email/status", { challengeId: ch3 })).b.verified === true, "poll -> verified");
done();
