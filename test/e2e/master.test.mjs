// Master sign-in with email verification. MODE=otp|link (server MASTER_EMAIL_VERIFICATION), master@example.com
import { BASE, Browser, done, masterBearer, nextMail, ok, rand } from "./lib.mjs";
const MODE = process.env.MODE ?? "otp";
const b = new Browser();
const call = async (path, auth, init = {}) => {
  const res = await fetch(BASE + path, { ...init, headers: { ...(auth ? { authorization: auth } : {}), ...(init.body ? { "content-type": "application/json" } : {}) } });
  return { s: res.status, b: res.status === 204 ? null : await res.json().catch(() => null) };
};

// password step
let r = await b.post("/auth/master/login", { username: "master", password: "wrong-password-1234567" });
ok(r.s === 401, "wrong password -> 401, no email");
r = await b.post("/auth/master/login", { username: "other", password: "correct-horse-battery-staple" });
ok(r.s === 401, "wrong username -> 401");
r = await call("/admin/clients", "Basic " + Buffer.from("master:correct-horse-battery-staple").toString("base64"));
ok(r.s === 401, "HTTP Basic with the master password no longer works (email step required)");
r = await b.post("/auth/master/login", { username: "MASTER@example.com", password: "correct-horse-battery-staple" });
ok(r.s === 200 && r.b.verify.method === (MODE === "link" ? "link" : "code") && r.b.verify.email === "m•••r@example.com", `login by email -> ${r.b.verify?.method} sent to ${r.b.verify?.email}`);
const ch = r.b.verify.challengeId;
const mail = await nextMail("master@example.com");
ok(/master/.test(mail.subject), `email subject: "${mail.subject}"`);
ok((await call("/admin/clients", null)).s === 401, "nothing usable before the email step");

let token;
if (MODE === "link") {
  ok(mail.link?.searchParams.get("master") === "1", "link carries master=1");
  r = await b.post("/auth/master/status", { challengeId: ch });
  ok(r.b.pending === true, "status: pending");
  r = await b.post("/auth/email/status", { challengeId: ch });
  ok(r.s === 400, "generic account status endpoint cannot consume a master challenge");
  r = await new Browser().post("/auth/email/link", { challengeId: ch, token: mail.token });
  ok(r.b.verified === true, "link opened (any browser) -> approved");
  r = await b.post("/auth/master/status", { challengeId: ch });
  ok(!!r.b.access_token && r.b.expires_in === 3600, "waiting /manage page gets a 1h session");
  token = r.b.access_token;
  ok((await b.post("/auth/master/status", { challengeId: ch })).s === 400, "single use");
} else {
  r = await b.post("/auth/email/verify", { challengeId: ch, code: mail.code });
  ok(r.s === 400, "generic /auth/email/verify cannot consume a master code");
  r = await b.post("/auth/master/verify", { challengeId: ch, code: mail.code === "000000" ? "111111" : "000000" });
  ok(r.s === 400 && /attempts left/.test(r.b.error_description), "wrong code -> attempts left");
  r = await b.post("/auth/master/verify", { challengeId: ch, code: mail.code });
  ok(r.s === 200 && !!r.b.access_token && r.b.username === "master", "correct code -> session");
  token = r.b.access_token;
  ok((await b.post("/auth/master/verify", { challengeId: ch, code: mail.code })).s === 400, "code single use");
}

const M = `Bearer ${token}`;
r = await call("/admin/clients", M);
ok(r.s === 200 && r.b.clients.some((c) => c.client_id === "keyvault-web"), "session -> list clients");
r = await call("/admin/users", M);
ok(r.s === 403 && /user.s access token/.test(r.b.error_description), `session cannot use /admin/users (${r.s} ${r.b?.error_description})`);
ok((await call("/secrets", M)).s === 403, "session cannot use /secrets");
r = await call("/admin/clients", M, { method: "POST", body: JSON.stringify({ client_id: "__master__", client_name: "x", grant_types: ["client_credentials"] }) });
ok(r.s === 400 && /reserved/.test(r.b.error_description), "client_id __master__ is reserved");
const id = "m-" + rand();
r = await call("/admin/clients", M, { method: "POST", body: JSON.stringify({ client_id: id, client_name: "By master", redirect_uris: ["https://m.example.com/cb"] }) });
ok(r.s === 201 && r.b.client_secret, "master creates a client");
r = await call(`/admin/clients/${id}`, M, { method: "DELETE" });
ok(r.s === 204, "master deletes it");
// a confidential client cannot introspect a master session
r = await call("/admin/clients", M, { method: "POST", body: JSON.stringify({ client_id: "rs-" + id, client_name: "RS", grant_types: ["client_credentials"], scope: "secrets" }) });
const rs = r.b;
const intro = await fetch(`${BASE}/oauth/introspect`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + Buffer.from(`${rs.client_id}:${rs.client_secret}`).toString("base64") }, body: new URLSearchParams({ token }) }).then((x) => x.json());
ok(intro.active === false, "introspection does not reveal master sessions");

// logout
r = await call("/auth/master/logout", M, { method: "POST" });
ok(r.s === 204 && (await call("/admin/clients", M)).s === 401, "logout ends the session");
if (MODE === "otp") ok(!!(await masterBearer("master@example.com")), "helper: sign in again");
done();
