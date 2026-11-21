// Owners of client management + disabling the master. Server: ADMIN_USERNAMES=admin_e2e, MASTER_CREDENTIALS=master:correct-horse-battery-staple
import { execSync } from "node:child_process";
import { BASE, Browser, done, ok, rand, registerWithCode, masterBearer } from "./lib.mjs";
let M = await masterBearer();
const call = async (path, auth, method = "GET") => {
  const res = await fetch(BASE + path, { method, headers: auth ? { authorization: auth } : {} });
  return { s: res.status, b: res.status === 204 ? null : await res.json().catch(() => null) };
};
const bearer = (t) => `Bearer ${t}`;

let r = await call("/admin/client-owners", M);
ok(r.s === 200 && r.b.owners.length === 0 && r.b.master.enabled && r.b.you.kind === "master", "start: no owners, master active");
r = await call("/admin/client-owners/master/disable", M, "POST");
ok(r.s === 409 && /owner first|at least one owner/.test(r.b.error_description), "cannot disable master without an owner");

// an admin is not a client owner
const adminUser = await registerWithCode(new Browser(), "admin_e2e");
r = await call("/admin/clients", bearer(adminUser.tokens.access_token));
ok(r.s === 403, "admin role alone cannot manage clients (403)");
r = await fetch(`${BASE}/admin/users/admin_e2e/roles`, { method: "PUT", headers: { authorization: bearer(adminUser.tokens.access_token), "content-type": "application/json" }, body: JSON.stringify({ roles: ["admin", "client_admin"] }) });
ok(r.status === 403, "admin cannot grant itself client_admin via /admin/users");

// owners
const o1 = "own1_" + rand(), o2 = "own2_" + rand();
const owner1 = await registerWithCode(new Browser(), o1);
const owner2 = await registerWithCode(new Browser(), o2);
r = await call(`/admin/client-owners/nobody_${rand()}`, M, "PUT");
ok(r.s === 404, "unknown username -> 404");
r = await call(`/admin/client-owners/${o1}`, M, "PUT");
ok(r.s === 200 && r.b.owners.some((o) => o.username === o1), "master adds an owner");
r = await call("/admin/clients", bearer(owner1.tokens.access_token));
ok(r.s === 200, "owner (client_admin) can manage clients right away");
r = await fetch(`${BASE}/admin/users/${o1}/roles`, { method: "PUT", headers: { authorization: bearer(adminUser.tokens.access_token), "content-type": "application/json" }, body: JSON.stringify({ roles: [] }) });
ok(r.status === 403, "admin cannot strip client_admin via /admin/users");
r = await fetch(`${BASE}/admin/users/${o1}/roles`, { method: "PUT", headers: { authorization: bearer(adminUser.tokens.access_token), "content-type": "application/json" }, body: JSON.stringify({ roles: ["admin", "client_admin"] }) });
ok(r.status === 200, "admin can still toggle admin when client_admin is kept as is");

// disable the master (by an owner)
r = await call("/admin/client-owners/master/disable", bearer(owner1.tokens.access_token), "POST");
ok(r.s === 200 && !r.b.master.enabled && r.b.master.disabledBy === o1, `owner disables master (disabledBy ${r.b.master?.disabledBy})`);
r = await call("/admin/clients", M);
ok(r.s === 401, "existing master session ended at once");
const login = (password) => fetch(`${BASE}/auth/master/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: "master", password }) }).then(async (x) => ({ s: x.status, b: await x.json() }));
r = await login("correct-horse-battery-staple");
ok(r.s === 401 && /disabled/.test(r.b.error_description), "master sign-in refused (says disabled)");
r = await login("wrong-password-1234567");
ok(r.s === 401 && !/disabled/.test(r.b.error_description), "wrong password does not learn it was disabled");

// last-owner protection
r = await call(`/admin/client-owners/${o1}`, bearer(owner1.tokens.access_token), "DELETE");
ok(r.s === 409, "last owner cannot be removed while master is disabled");
r = await call(`/admin/client-owners/${o2}`, bearer(owner1.tokens.access_token), "PUT");
ok(r.s === 200 && r.b.owners.length === 2, "owner adds a second owner");
r = await call(`/admin/client-owners/${o1}`, bearer(owner2.tokens.access_token), "DELETE");
ok(r.s === 200 && r.b.owners.length === 1, "now an owner can be removed");
r = await call("/admin/clients", bearer(owner1.tokens.access_token));
ok(r.s === 403, "removed owner loses access immediately");
r = await call(`/admin/client-owners/${o2}`, bearer(owner2.tokens.access_token), "DELETE");
ok(r.s === 409, "the remaining owner cannot remove itself");

// re-enable by an owner
r = await call("/admin/client-owners/master/enable", bearer(owner2.tokens.access_token), "POST");
ok(r.s === 200 && r.b.master.enabled, "owner re-enables master");
M = await masterBearer();
ok((await call("/admin/clients", M)).s === 200, "master works again (new sign-in)");

// master disables itself; recovery CLI
r = await call("/admin/client-owners/master/disable", M, "POST");
ok(r.s === 200 && r.b.master.disabledBy === "master:master", "master can disable itself");
ok((await call("/admin/client-owners/master/enable", M, "POST")).s === 401, "a disabled master cannot re-enable itself");
execSync("pnpm -s master:enable", { cwd: process.env.REPO ?? process.cwd(), env: { ...process.env }, stdio: "pipe" });
M = await masterBearer();
ok((await call("/admin/clients", M)).s === 200, "pnpm master:enable (server access) restores it");
done();
