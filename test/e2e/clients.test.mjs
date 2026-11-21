// OAuth client management + per-client settings. Server: ADMIN_USERNAMES=admin_e2e, OIDC_RETIRED_KEY_GRACE_SEC=3600,
// built-in client in code mode, redirect http://localhost:3001/callback.
import { BASE, Browser, claims, done, exchange, nextMail, ok, rand, registerWithCode, revoke, token, masterBearer } from "./lib.mjs";

const ui = new Browser();
const admin = await registerWithCode(ui, "admin_e2e");
const T = admin.tokens.access_token;
// client management now needs the client_admin role: the master makes this user an owner
await fetch(`${BASE}/admin/client-owners/admin_e2e`, { method: "PUT", headers: { authorization: await masterBearer() } });
ok(!!T && !!admin.tokens.refresh_token, "admin signed in through the built-in client (public, PKCE)");

// --- discovery
const disco = await (await fetch(`${BASE}/.well-known/openid-configuration`)).json();
ok(["none", "client_secret_basic", "client_secret_post"].every((m) => disco.token_endpoint_auth_methods_supported.includes(m)), "discovery lists none / client_secret_basic / client_secret_post");

// --- list: seeded client
let r = await ui.json("/admin/clients", T);
const seeded = r.b.clients.find((c) => c.client_id === "keyvault-web");
ok(seeded?.token_endpoint_auth_method === "none" && seeded.initiate_login_uri === "http://localhost:3001/" && !("client_secret" in seeded), `seeded keyvault-web: public, initiate_login_uri ${seeded?.initiate_login_uri}, no secret shown`);
r = await new Browser().json("/admin/clients", "nope");
ok(r.s === 401, "admin API needs a token");

// --- validation (RFC 7591 error codes)
const post = (body) => ui.json("/admin/clients", T, { method: "POST", body: JSON.stringify(body) });
r = await post({ client_name: "Bad", redirect_uris: ["http://evil.example.com/cb"] });
ok(r.s === 400 && r.b.error === "invalid_redirect_uri", `http on non-loopback -> invalid_redirect_uri`);
r = await post({ client_name: "Bad", redirect_uris: ["https://a.example.com/cb#x"] });
ok(r.s === 400 && r.b.error === "invalid_redirect_uri", "fragment -> invalid_redirect_uri");
r = await post({ client_name: "Bad", redirect_uris: ["https://a.example.com/cb"], scope: "openid admin" });
ok(r.s === 400 && r.b.error === "invalid_client_metadata", `unknown scope -> invalid_client_metadata`);
r = await post({ client_name: "Bad", redirect_uris: ["https://a.example.com/cb"], id_token_lifetime: 7200 });
ok(r.s === 400 && /3600/.test(r.b.error_description), `id_token_lifetime above key grace -> "${r.b.error_description}"`);
r = await post({ client_name: "Bad", redirect_uris: ["https://a.example.com/cb"], grant_types: ["refresh_token"] });
ok(r.s === 400, "grant_types without authorization_code rejected");
r = await post({ client_name: "Native", client_id: "native-" + rand(), token_endpoint_auth_method: "none", redirect_uris: ["com.example.app:/oauth2redirect"] });
ok(r.s === 201 && !r.b.client_secret, "private-use scheme redirect (RFC 8252) accepted for a public client, no secret");

// --- register a confidential client with its own settings
const svcId = "svc-" + rand();
r = await post({
  client_id: svcId, client_name: "Billing Portal", redirect_uris: ["https://billing.example.com/cb"],
  scope: "openid email", email_verification: "link", access_token_lifetime: 120, id_token_lifetime: 600
});
ok(r.s === 201 && r.b.client_id === svcId && r.b.client_secret?.length === 43 && r.b.client_secret_expires_at === 0, "confidential client registered: secret shown once, client_secret_expires_at 0");
ok(r.b.token_endpoint_auth_method === "client_secret_basic" && r.b.grant_types.join() === "authorization_code", "RFC 7591 defaults: client_secret_basic, grant_types [authorization_code]");
ok(r.h.get("cache-control") === "no-store", "registration response is no-store");
let secret = r.b.client_secret;
r = await post({ client_id: svcId, client_name: "Dup", redirect_uris: ["https://x.example.com/cb"] });
ok(r.s === 409, "duplicate client_id -> 409");
r = await ui.json(`/admin/clients/${svcId}`, T);
ok(r.s === 200 && !r.b.client_secret, "GET client never returns the secret");

// --- authorization request checks
const b = new Browser();
let a = await b.authorize({ clientId: svcId, redirectUri: "https://evil.example.com/cb" });
ok(a.status === 400, "unregistered redirect_uri -> 400, no redirect");
a = await b.authorize({ clientId: "nope", redirectUri: "https://billing.example.com/cb" });
ok(a.status === 400, "unknown client -> 400");
a = await b.authorize({ clientId: svcId, redirectUri: "https://billing.example.com/cb", scope: "openid secrets" });
ok(a.location?.origin === "https://billing.example.com" && a.location.searchParams.get("error") === "invalid_scope", "scope beyond the client's -> redirect with invalid_scope");

// --- sign in (username, verified -> no email) and token endpoint client auth
a = await b.authorize({ clientId: svcId, redirectUri: "https://billing.example.com/cb", scope: null });
r = await b.post("/auth/login/password", { request_id: a.rid, username: "admin_e2e", password: admin.password });
ok(!!r.b.redirect?.startsWith("https://billing.example.com/cb?code="), "login on the client's request -> its redirect_uri");
const redirect = r.b.redirect;
r = await exchange(redirect, a, { none: svcId });
ok(r.s === 401 && r.b.error === "invalid_client", "confidential client without secret -> 401 invalid_client");
r = await exchange(redirect, a, { post: [svcId, secret] });
ok(r.s === 401, "wrong method (post instead of registered basic) -> 401");
r = await exchange(redirect, a, { basic: [svcId, "wrong"] });
ok(r.s === 401 && /Basic/.test(r.h.get("www-authenticate") ?? ""), "wrong secret via Basic -> 401 + WWW-Authenticate: Basic");
r = await exchange(redirect, a, { basic: [svcId, secret] });
const svcTokens = r.b;
ok(r.s === 200 && !svcTokens.refresh_token && svcTokens.expires_in === 120 && svcTokens.scope === "email openid", `Basic auth -> tokens: expires_in ${svcTokens.expires_in}, scope "${svcTokens.scope}" (client default), no refresh_token`);
const idc = claims(svcTokens.id_token);
ok(idc.exp - idc.iat === 600 && idc.aud === svcId, `ID Token: aud = client, lifetime ${idc.exp - idc.iat}s (client id_token_lifetime)`);

// --- revocation: client authentication, own tokens only
r = await revoke(admin.tokens.access_token, { basic: [svcId, secret] });
ok(r.s === 200, "revoking another client's token -> 200 ...");
ok((await ui.json("/auth/me", T)).s === 200, "... but it is NOT revoked");
r = await revoke(svcTokens.access_token, { none: svcId });
ok(r.s === 401, "confidential client revoking without its secret -> 401");
r = await revoke(svcTokens.access_token, { basic: [svcId, secret] });
ok(r.s === 200 && (await b.json("/oauth/userinfo", svcTokens.access_token)).s === 401, "own token revoked");

// --- secret rotation
r = await ui.json(`/admin/clients/${svcId}/secret`, T, { method: "POST" });
const newSecret = r.b.client_secret;
ok(r.s === 200 && newSecret && newSecret !== secret, "rotate -> new secret");
ok((await revoke("", { basic: [svcId, secret] })).s === 401, "old secret rejected");
ok((await revoke("", { basic: [svcId, newSecret] })).s === 200, "new secret accepted");
secret = newSecret;

// --- per-client email: link, no initiate_login_uri -> link finishes the original request
a = await b.authorize({ clientId: svcId, redirectUri: "https://billing.example.com/cb", scope: "openid email" });
r = await b.post("/auth/login/password", { request_id: a.rid, username: admin.email, password: admin.password });
ok(r.b.verify?.method === "link", "client email_verification=link -> email login gets a link");
let mail = await nextMail(admin.email);
ok(mail.subject === "Sign in to Billing Portal", `email names the client: "${mail.subject}"`);
ok(mail.link.origin === "http://localhost:3001", `link opens the auth UI the request came from (${mail.link.origin})`);
const phone = new Browser("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");
r = await phone.post("/auth/email/link", { challengeId: mail.id, token: mail.token });
ok(!!r.b.redirect && new URL(r.b.redirect).searchParams.get("state") === a.state, "no initiate_login_uri -> link completes the original request (original state)");
r = await exchange(r.b.redirect, a, { basic: [svcId, secret] });
ok(r.s === 200, "client exchanges it with its original PKCE verifier");

// --- with initiate_login_uri -> continue there, then resume on the client's fresh request
r = await ui.json(`/admin/clients/${svcId}`, T, { method: "PUT", body: JSON.stringify({ client_name: "Billing Portal", redirect_uris: ["https://billing.example.com/cb"], scope: "openid email", email_verification: "link", initiate_login_uri: "https://billing.example.com/login", access_token_lifetime: 120, id_token_lifetime: 600 }) });
ok(r.s === 200 && r.b.initiate_login_uri === "https://billing.example.com/login" && !r.b.client_secret, "PUT update (confidential stays confidential, secret kept)");
a = await b.authorize({ clientId: svcId, redirectUri: "https://billing.example.com/cb", scope: "openid email" });
await b.post("/auth/login/password", { request_id: a.rid, username: admin.email, password: admin.password });
mail = await nextMail(admin.email);
const tab = new Browser();
r = await tab.post("/auth/email/link", { challengeId: mail.id, token: mail.token });
const cont = r.b.continue && new URL(r.b.continue);
ok(cont?.href.startsWith("https://billing.example.com/login?iss="), `link -> continue to initiate_login_uri (${cont?.href})`);
ok(tab.has("kv_email_link") && tab.has("kv_email_link_pending"), "link kept in cookies for the next sign-in");
// the client (on its initiate_login_uri) starts a fresh request in that tab
const other = await tab.authorize(); // keyvault-web request: different client
r = await tab.post("/auth/email/link/resume", { request_id: other.rid });
ok(r.s === 400 && /different app/.test(r.b.error_description), "link cannot be used for another client's request");
// cookie was cleared by the failed attempt; open the link again
r = await tab.post("/auth/email/link", { challengeId: mail.id, token: mail.token });
const fresh = await tab.authorize({ clientId: svcId, redirectUri: "https://billing.example.com/cb", scope: "openid email" });
r = await tab.post("/auth/email/link/resume", { request_id: fresh.rid });
ok(!!r.b.redirect && new URL(r.b.redirect).searchParams.get("state") === fresh.state, "resume on the client's fresh request -> redirect with ITS state");
ok(!tab.has("kv_email_link"), "link cookie cleared");
r = await exchange(r.b.redirect, fresh, { basic: [svcId, secret] });
ok(r.s === 200 && claims(r.b.id_token).email_verified === true, "fresh request's PKCE verifier exchanges the code");
const svcAccess = r.b.access_token;

// --- switching to public drops the secret
r = await ui.json(`/admin/clients/${svcId}`, T, { method: "PUT", body: JSON.stringify({ client_id: "other", client_name: "x", redirect_uris: ["https://billing.example.com/cb"] }) });
ok(r.s === 400, "client_id cannot change");

// --- built-in client: per-client email method switch to link (no env)
r = await ui.json("/admin/clients/keyvault-web", T);
const kv = r.b;
r = await ui.json("/admin/clients/keyvault-web", T, { method: "PUT", body: JSON.stringify({ ...kv, email_verification: "link" }) });
ok(r.s === 200 && r.b.email_verification === "link", "built-in client switched to link in the DB");
a = await ui.authorize();
r = await ui.post("/auth/login/password", { request_id: a.rid, username: admin.email, password: admin.password });
ok(r.b.verify?.method === "link", "UI sign-in by email now sends a link");
mail = await nextMail(admin.email);
ok(mail.subject === "Sign in to Key Vault", `subject uses the built-in client's name: "${mail.subject}"`);
await ui.json("/admin/clients/keyvault-web", T, { method: "PUT", body: JSON.stringify({ ...kv }) });

// --- delete
r = await ui.json("/admin/clients/keyvault-web", T, { method: "DELETE" });
ok(r.s === 409, "cannot delete the client you are signed in with");
r = await ui.json(`/admin/clients/${svcId}`, T, { method: "DELETE" });
ok(r.s === 204, "delete client");
ok((await b.json("/oauth/userinfo", svcAccess)).s === 401, "its tokens are revoked");
a = await b.authorize({ clientId: svcId, redirectUri: "https://billing.example.com/cb" });
ok(a.status === 400, "deleted client cannot authorize");

done();
