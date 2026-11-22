// Changing the password while signed in (POST /auth/me/password).
import { Browser, BASE, exchange, done, nextMail, ok, rand, registerWithCode, token } from "./lib.mjs";

const b = new Browser();
const name = `pc_${rand()}`;
const { email, password, tokens: s1 } = await registerWithCode(b, name);

/** A second, independent sign-in (another session) with username + password. */
async function signIn(pw) {
  const other = new Browser("Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/133.0");
  const a = await other.authorize();
  const r = await other.post("/auth/login/password", { request_id: a.rid, username: name, password: pw });
  if (!r.b?.redirect) return { s: r.s };
  return { s: r.s, tokens: (await exchange(r.b.redirect, a, { none: "keyvault-web" })).b };
}
const change = (at, body) => b.json("/auth/me/password", at, { method: "POST", body: JSON.stringify(body) });
const me = async (at) => (await b.json("/auth/me", at)).s;
const refreshes = async (t) => (await token({ grant_type: "refresh_token", refresh_token: t.refresh_token }, { none: "keyvault-web" })).s === 200;

const s2 = (await signIn(password)).tokens;
ok(!!s2?.access_token, "second session signed in");

// ------------------------------------------------------------------ refused
const NEW1 = "first-new-pass-123";
let r = await change(s1.access_token, { currentPassword: "wrong-password", newPassword: NEW1 });
ok(r.s === 403 && r.b.error === "access_denied", `wrong current password -> 403 (not 401, which would sign the UI out) (${r.s})`);
ok((await me(s1.access_token)) === 200, "session still valid after a wrong attempt");
ok((await change(s1.access_token, { newPassword: NEW1 })).s === 400, "missing current password -> 400");
ok((await change(s1.access_token, { currentPassword: password, newPassword: "short" })).s === 400, "new password under 8 chars -> 400");
ok((await change(s1.access_token, { currentPassword: password, newPassword: password })).s === 400, "same as the current one -> 400");
const anon = await fetch(`${BASE}/auth/me/password`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ currentPassword: password, newPassword: NEW1 }) });
ok(anon.status === 401, "without a token -> 401");
ok((await signIn(password)).s === 200, "nothing changed yet: the old password still signs in");

// ------------------------------------------------------------------ change, signing out the other sessions (default)
r = await change(s1.access_token, { currentPassword: password, newPassword: NEW1 });
ok(r.s === 200 && r.b.changed === true && r.b.signedOutOthers === true, `change -> 200, others signed out (${r.s} ${r.b?.error_description ?? ""})`);
ok((await me(s1.access_token)) === 200 && (await refreshes(s1)), "this session stays signed in (access + refresh)");
ok((await me(s2.access_token)) === 401, "other session's access token revoked");
ok(!(await refreshes(s2)), "other session's refresh token revoked");
const notice = await nextMail(email);
ok(/password was changed/i.test(notice.subject), `"password changed" notice emailed (${notice.subject})`);

ok((await signIn(password)).s === 401, "old password rejected");
const s3 = (await signIn(NEW1)).tokens;
ok(!!s3?.access_token, "new password signs in");

// ------------------------------------------------------------------ change, keeping the other sessions
const NEW2 = "second-new-pass-456";
const s4 = (await signIn(NEW1)).tokens;
r = await change(s3.access_token, { currentPassword: NEW1, newPassword: NEW2, signOutOthers: false });
ok(r.s === 200 && r.b.signedOutOthers === false, "change with signOutOthers=false -> 200");
ok((await me(s4.access_token)) === 200, "other sessions kept when asked");
await nextMail(email);
ok((await signIn(NEW2)).s === 200, "the newest password signs in");

done();
