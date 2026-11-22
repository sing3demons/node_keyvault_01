// Forgot password. MODE=code|link (built-in client's email_verification).
import { Browser, done, exchange, nextMail, ok, rand, registerWithCode, token } from "./lib.mjs";

const MODE = process.env.MODE ?? "code";
const NEW_PASSWORD = "brand-new-pass-456";

const b = new Browser();
const name = `pr_${rand()}`;

/** Registers and signs in on the built-in client, through its code or link step. */
async function registerUser(browser, username) {
  if (MODE === "code") return registerWithCode(browser, username);
  const email = `${username}@example.com`, password = "password123";
  const reg = await browser.authorize();
  await browser.post("/auth/register", { request_id: reg.rid, username, email, password, profiles: [{ lang: "en", firstName: "R", lastName: "P" }] });
  const m = await nextMail(email);
  await browser.post("/auth/email/link", { challengeId: m.id, token: m.token });
  const a = await browser.authorize();
  const r = await browser.post("/auth/email/link/resume", { request_id: a.rid });
  return { email, password, tokens: (await exchange(r.b.redirect, a, { none: "keyvault-web" })).b };
}
const { email, password, tokens } = await registerUser(b, name);

const forgot = async (identifier, withRequest = true) => {
  const a = withRequest ? await b.authorize() : null;
  return b.post("/auth/password/forgot", { identifier, ...(a ? { request_id: a.rid } : {}) });
};
const secretOf = (m) => (MODE === "link" ? { token: m.token } : { code: m.code });

// ------------------------------------------------------------------ request: same answer whether or not the account exists
const ghostUser = await forgot(`nobody_${rand()}`);
ok(ghostUser.s === 200 && ghostUser.b.challengeId && ghostUser.b.email === undefined && ghostUser.b.reason === "reset_password", "unknown username -> 200, no address shown");
ok(ghostUser.b.method === MODE, `method follows the client (${ghostUser.b.method})`);
const ghostMail = await forgot(`nobody_${rand()}@example.com`);
ok(ghostMail.s === 200 && /^n•••\d@example\.com$|^n•••.@example\.com$/.test(ghostMail.b.email ?? ""), `unknown email -> 200, masked input echoed (${ghostMail.b.email})`);

const r1 = await forgot(name);
ok(r1.s === 200 && r1.b.email === undefined, "real username -> 200, account address not revealed");
ok(Object.keys(r1.b).sort().join() === Object.keys(ghostUser.b).sort().join(), "response has the same shape as for an unknown account");
const m1 = await nextMail(email);
ok(/password/i.test(m1.subject) && (MODE === "link" ? m1.link?.pathname === "/reset-password" && m1.id === r1.b.challengeId : /^\d{6}$/.test(m1.code ?? "")), `reset email sent (${m1.subject})`);

const r2 = await forgot(email);
ok(r2.s === 200 && r2.b.challengeId === r1.b.challengeId && r2.b.email === "p•••" + email.split("@")[0].slice(-1) + "@example.com", "asking again within the cooldown reuses the pending challenge (no new email)");
ok((await forgot(name, false)).s === 200, "works without request_id too (API clients)");

// ------------------------------------------------------------------ the reset code / link works only on /auth/password/reset
if (MODE === "code") {
  ok((await b.post("/auth/email/verify", { challengeId: r1.b.challengeId, code: m1.code })).s === 400, "reset code refused by /auth/email/verify");
} else {
  ok((await b.post("/auth/email/link", { challengeId: r1.b.challengeId, token: m1.token })).s === 400, "reset link refused by /auth/email/link");
}
ok((await b.post("/auth/email/resend", { challengeId: r1.b.challengeId })).s === 400, "reset challenge refused by /auth/email/resend");

// ------------------------------------------------------------------ validation
ok((await b.post("/auth/password/reset", { challengeId: r1.b.challengeId, ...secretOf(m1), password: "short" })).s === 400, "new password under 8 chars -> 400");
ok((await b.post("/auth/password/reset", { challengeId: r1.b.challengeId, password: NEW_PASSWORD })).s === 400, "missing code/token -> 400");
ok((await b.post("/auth/password/reset", { challengeId: r1.b.challengeId, code: "000000", token: "abc", password: NEW_PASSWORD })).s === 400, "both code and token -> 400");
const wrong = MODE === "link" ? { token: "A".repeat(43) } : { code: m1.code === "000000" ? "111111" : "000000" };
const bad = await b.post("/auth/password/reset", { challengeId: r1.b.challengeId, ...wrong, password: NEW_PASSWORD });
ok(bad.s === 400 && bad.b.error === "invalid_code", `wrong ${MODE} -> 400 invalid_code (${bad.b?.error_description})`);
ok((await b.post("/auth/password/reset", { challengeId: ghostUser.b.challengeId, code: "123456", password: NEW_PASSWORD })).s === 400, "unknown account's decoy challenge -> 400");

// ------------------------------------------------------------------ reset
const res = await b.post("/auth/password/reset", { challengeId: r1.b.challengeId, ...secretOf(m1), password: NEW_PASSWORD });
ok(res.s === 200 && res.b.reset === true, `reset -> 200 (${res.s} ${res.b?.error_description ?? ""})`);
ok(res.b.continue?.startsWith("http://localhost:3001/") && new URL(res.b.continue).searchParams.has("iss"), "continue = the client's initiate_login_uri");
const again = await b.post("/auth/password/reset", { challengeId: r1.b.challengeId, ...secretOf(m1), password: "yet-another-pass" });
ok(again.s === 400, "the code / link is single use");

const notice = await nextMail(email);
ok(/password was changed/i.test(notice.subject), `"password changed" notice emailed (${notice.subject})`);

// ------------------------------------------------------------------ every session ended
ok((await b.json("/auth/me", tokens.access_token)).s === 401, "old access token no longer works");
const rt = await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }, { none: "keyvault-web" });
ok(rt.s === 400, `old refresh token no longer works (${rt.s} ${rt.b?.error})`);

// ------------------------------------------------------------------ signing in
const a1 = await b.authorize();
ok((await b.post("/auth/login/password", { request_id: a1.rid, username: name, password })).s === 401, "old password rejected");
const a2 = await b.authorize();
const lp = await b.post("/auth/login/password", { request_id: a2.rid, username: name, password: NEW_PASSWORD });
ok(lp.s === 200 && lp.b.redirect, `new password signs in (${lp.s} ${lp.b?.error_description ?? ""})`);

// a fresh request after a finished reset starts a new challenge
const r3 = await forgot(name);
ok(r3.s === 200 && r3.b.challengeId !== r1.b.challengeId, "after a reset, asking again starts a new challenge");
await nextMail(email);

done();
