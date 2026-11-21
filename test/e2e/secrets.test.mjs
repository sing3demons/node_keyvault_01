// Secret owners + sharing: exercises UserDirectory.findByUsername (share / transfer) and findByIds (listing names).
import { BASE, Browser, done, ok, rand, registerWithCode } from "./lib.mjs";
const a = await registerWithCode(new Browser(), "own_" + rand());
const b = await registerWithCode(new Browser(), "shr_" + rand());
const c = await registerWithCode(new Browser(), "thr_" + rand());
const nameOf = (u) => u.email.split("@")[0];
const api = (tok, path, method = "GET", body) =>
  fetch(BASE + path, { method, headers: { authorization: `Bearer ${tok.tokens.access_token}`, ...(body ? { "content-type": "application/json" } : {}) }, body: body && JSON.stringify(body) })
    .then(async (r) => ({ s: r.status, b: r.status === 204 ? null : await r.json().catch(() => null) }));
const names = ["e2e-" + rand(), "e2e-" + rand()];
for (const n of names) ok((await api(a, `/secrets/${n}`, "PUT", { value: "v-" + n })).s === 201, `A creates ${n}`);
await api(c, `/secrets/${"e2e-c-" + rand()}`, "PUT", { value: "x" });

let r = await api(a, `/secrets/${names[0]}/grants/${nameOf(b)}`, "PUT", { permissions: ["read"] });
ok(r.s === 200 && r.b.grants.some((g) => g.user.username === nameOf(b)), "share by username (findByUsername) -> grant shows B's username");
r = await api(a, `/secrets/${names[0]}/grants/nobody_${rand()}`, "PUT", { permissions: ["read"] });
ok(r.s === 404, "unknown username -> 404");

r = await api(b, "/secrets");
const list = r.b.secrets.filter((s) => s.name.startsWith("e2e-"));
const owners = new Set(list.map((s) => s.owner?.username));
ok(r.s === 200 && owners.has(nameOf(a)) && owners.has(nameOf(c)), `listing resolves every owner's name in one go (findByIds): ${[...owners].join(", ")}`);
ok(list.find((s) => s.name === names[0])?.access.read === true && list.find((s) => s.name === names[1])?.access.read === false, "B can read only the shared secret");
r = await api(b, `/secrets/${names[0]}`);
ok(r.s === 200 && r.b.value === "v-" + names[0], "B reads the shared value");

r = await api(a, `/secrets/${names[1]}/owner`, "PUT", { username: nameOf(c) });
ok(r.s === 200 && r.b.owner.username === nameOf(c), "transfer ownership by username");
r = await api(a, `/secrets/${names[0]}/grants`);
ok(r.b.grants.length === 1 && r.b.grants[0].user.username === nameOf(b), "grants list shows usernames");
for (const n of names) await api(n === names[1] ? c : a, `/secrets/${n}`, "DELETE");
done();
