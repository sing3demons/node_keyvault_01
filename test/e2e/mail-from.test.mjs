import { BASE, Browser, done, masterBearer, ok, rand, registerWithCode } from "./lib.mjs";
const M = await masterBearer();
const api = (path, method = "GET", body) => fetch(BASE + path, { method, headers: { authorization: M, ...(body ? { "content-type": "application/json" } : {}) }, body: body && JSON.stringify(body) }).then(async (r) => ({ s: r.status, b: await r.json().catch(() => null) }));
const fromOf = async (to) => {
  for (let i = 0; i < 30; i++) {
    const l = await (await fetch(`http://localhost:8025/api/v1/search?query=${encodeURIComponent("to:" + to)}`)).json();
    if (l.messages?.length) return l.messages[0].From;
    await new Promise((r) => setTimeout(r, 200));
  }
};
let r = await api("/admin/clients");
ok(r.b.default_mail_from === "Key Vault Test <no-reply@kv.test>" && !("mail_from" in r.b.clients[0]), `list returns default_mail_from (${r.b.default_mail_from}); seeded client has none`);
const base = { client_name: "Billing", redirect_uris: ["https://b.example.com/cb"], scope: "openid email", email_verification: "code" };
for (const bad of ["Bad\r\nBcc: x@y.com <a@b.co>", "Name <not-an-email>", "a@b"]) {
  r = await api("/admin/clients", "POST", { ...base, mail_from: bad });
  ok(r.s === 400 && r.b.error === "invalid_client_metadata", `rejects mail_from ${JSON.stringify(bad)}`);
}
const id = "bill-" + rand();
r = await api("/admin/clients", "POST", { ...base, client_id: id, mail_from: "Billing Team <billing@billing.example.com>" });
ok(r.s === 201 && r.b.mail_from === "Billing Team <billing@billing.example.com>", "client created with its own sender");
const secret = r.b.client_secret;

// an email sent for this client uses its sender
const user = await registerWithCode(new Browser(), "mf_" + rand());
const b = new Browser();
const a = await b.authorize({ clientId: id, redirectUri: "https://b.example.com/cb", scope: "openid email" });
r = await b.post("/auth/login/password", { request_id: a.rid, username: user.email, password: user.password });
ok(r.b.verify?.method === "code", "email login for the client -> code email");
let from = await fromOf(user.email);
ok(from?.Address === "billing@billing.example.com" && from?.Name === "Billing Team", `From: ${from?.Name} <${from?.Address}>`);

// registration (built-in client, no mail_from) used the default
const other = "mf2_" + rand();
await registerWithCode(new Browser(), other);
from = await fromOf(`${other}@example.com`);
ok(from?.Address === "no-reply@kv.test", `built-in client uses MAIL_FROM: ${from?.Name} <${from?.Address}>`);

// clearing it (PUT without mail_from) -> back to default
r = await api(`/admin/clients/${id}`, "PUT", { ...base });
ok(r.s === 200 && !("mail_from" in r.b), "PUT without mail_from clears it");
r = await api(`/admin/clients/${id}`, "PUT", { ...base, mail_from: "alerts@billing.example.com" });
ok(r.b.mail_from === "alerts@billing.example.com", "plain address accepted");
done();
