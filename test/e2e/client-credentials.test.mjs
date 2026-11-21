// client_credentials + introspection. Server: MASTER_CREDENTIALS=base64("master:correct-horse-battery-staple")
import { BASE, Browser, done, ok, rand, registerWithCode, revoke, token, masterBearer } from "./lib.mjs";
let M = await masterBearer();
const admin = (path, init = {}) =>
  fetch(BASE + path, { ...init, headers: { authorization: M, ...(init.body ? { "content-type": "application/json" } : {}) } }).then(async (r) => ({ s: r.status, b: await r.json().catch(() => null) }));
const introspect = async (tok, auth) => {
  const res = await fetch(`${BASE}/oauth/introspect`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + Buffer.from(`${auth[0]}:${auth[1]}`).toString("base64") }, body: new URLSearchParams({ token: tok }) });
  return { s: res.status, b: await res.json().catch(() => null) };
};

// --- metadata rules
let r = await admin("/admin/clients", { method: "POST", body: JSON.stringify({ client_name: "x", token_endpoint_auth_method: "none", grant_types: ["client_credentials"] }) });
ok(r.s === 400 && /confidential/.test(r.b.error_description), "public client cannot have client_credentials");
r = await admin("/admin/clients", { method: "POST", body: JSON.stringify({ client_name: "x", grant_types: ["client_credentials", "refresh_token"] }) });
ok(r.s === 400, "refresh_token without authorization_code rejected");
r = await admin("/admin/clients", { method: "POST", body: JSON.stringify({ client_name: "x", grant_types: ["authorization_code"] }) });
ok(r.s === 400 && r.b.error === "invalid_redirect_uri", "authorization_code without redirect_uris rejected");

// --- a machine client: client_credentials only, no redirect URIs
const id = "svc-" + rand();
r = await admin("/admin/clients", { method: "POST", body: JSON.stringify({ client_id: id, client_name: "Batch job", grant_types: ["client_credentials"], scope: "openid secrets", access_token_lifetime: 300 }) });
ok(r.s === 201 && r.b.redirect_uris.length === 0 && r.b.grant_types.join() === "client_credentials", "machine client: client_credentials only, no redirect_uris");
const secret = r.b.client_secret;

r = await token({ grant_type: "client_credentials" }, { basic: [id, "wrong"] });
ok(r.s === 401 && r.b.error === "invalid_client", "wrong secret -> 401 invalid_client");
r = await token({ grant_type: "client_credentials" }, { basic: [id, secret] });
ok(r.s === 200 && r.b.scope === "secrets" && r.b.expires_in === 300 && !r.b.refresh_token && !r.b.id_token, `token: scope "${r.b.scope}" (OIDC scopes dropped), expires_in ${r.b.expires_in}, no refresh / id token`);
const cc = r.b.access_token;
r = await token({ grant_type: "client_credentials", scope: "openid" }, { basic: [id, secret] });
ok(r.s === 400 && r.b.error === "invalid_scope", "asking for openid -> invalid_scope");
r = await token({ grant_type: "client_credentials", scope: "secrets" }, { basic: [id, secret] });
ok(r.s === 200, "explicit scope=secrets ok");
r = await token({ grant_type: "client_credentials" }, { none: "keyvault-web" });
ok(r.s === 400 && r.b.error === "unauthorized_client", "public UI client -> unauthorized_client");
r = await token({ grant_type: "password", username: "a", password: "b" }, { basic: [id, secret] });
ok(r.s === 400 && r.b.error === "unsupported_grant_type", "other grants -> unsupported_grant_type");

// --- code-flow client without client_credentials
const web = "web-" + rand();
r = await admin("/admin/clients", { method: "POST", body: JSON.stringify({ client_id: web, client_name: "Web", redirect_uris: ["https://w.example.com/cb"] }) });
const webSecret = r.b.client_secret;
r = await token({ grant_type: "client_credentials" }, { basic: [web, webSecret] });
ok(r.s === 400 && r.b.error === "unauthorized_client", "client not registered for client_credentials -> unauthorized_client");

// --- using the token
const b = new Browser();
r = await b.json("/secrets", cc);
ok(r.s === 403 && /user's access token/.test(r.b.error_description), "user-only endpoints answer 403 for a client token");
r = await b.json("/oauth/userinfo", cc);
ok(r.s === 403, "userinfo: 403 (no user)");

// --- introspection (RFC 7662)
r = await introspect(cc, [web, webSecret]);
ok(r.s === 200 && r.b.active === true && r.b.client_id === id && r.b.sub === id && r.b.scope === "secrets" && !r.b.username, `introspect client token: active, sub = client_id`);
const user = await registerWithCode(new Browser(), "cc_" + rand());
r = await introspect(user.tokens.access_token, [web, webSecret]);
ok(r.b.active === true && r.b.client_id === "keyvault-web" && !!r.b.username, `introspect user token: active, username ${r.b.username}`);
r = await introspect(user.tokens.refresh_token, [web, webSecret]);
ok(r.b.active === true && r.b.token_type === "refresh_token", "introspect refresh token");
r = await introspect("nonsense", [web, webSecret]);
ok(r.s === 200 && r.b.active === false && Object.keys(r.b).length === 1, "unknown token -> { active: false } only");
r = await introspect(cc, [web, "wrong"]);
ok(r.s === 401, "introspection needs client authentication");
r = await fetch(`${BASE}/oauth/introspect`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: cc, client_id: "keyvault-web" }) });
ok(r.status === 401, "public client cannot introspect");

// --- revoke the client token
r = await revoke(cc, { basic: [id, secret] });
ok(r.s === 200 && (await introspect(cc, [web, webSecret])).b.active === false, "revoked client token -> inactive");

// --- discovery
const d = await (await fetch(`${BASE}/.well-known/openid-configuration`)).json();
ok(d.grant_types_supported.includes("client_credentials") && d.introspection_endpoint?.endsWith("/oauth/introspect"), "discovery: client_credentials + introspection_endpoint");
done();
