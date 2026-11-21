// OAuth2 Authorization Code + PKCE client for the SPA, plus WebAuthn (passkey) helpers.

export const CLIENT_ID = "keyvault-web";
/** "openid profile email" => an ID Token with name/email claims; "secrets" => access to the API. */
const SCOPE = "openid profile email secrets";
const redirectUri = () => `${location.origin}/callback`;

const K = {
  verifier: "oauth.pkce_verifier",
  state: "oauth.state",
  nonce: "oauth.nonce",
  returnTo: "oauth.return_to",
  tokens: "oauth.tokens",
  emailLink: "auth.email_link"
};

interface Tokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  /** Latest ID Token (kept when a refresh response has none). */
  idToken?: string;
}

/** Who is signed in, from the ID Token's claims (OIDC Core §5.1) — available without an API call. */
export interface Identity {
  sub: string;
  name?: string;
  preferredUsername?: string;
  email?: string;
  locale?: string;
}

type TokenResponse = { access_token: string; refresh_token: string; expires_in: number; id_token?: string };

// ------------------------------------------------------------------ storage (per-tab)

const store = {
  get: (k: string) => {
    try {
      return sessionStorage.getItem(k);
    } catch {
      return null;
    }
  },
  set: (k: string, v: string) => {
    try {
      sessionStorage.setItem(k, v);
    } catch {
      /* ignore */
    }
  },
  del: (k: string) => {
    try {
      sessionStorage.removeItem(k);
    } catch {
      /* ignore */
    }
  }
};

let tokens: Tokens | null = (() => {
  const raw = store.get(K.tokens);
  return raw ? (JSON.parse(raw) as Tokens) : null;
})();

function saveTokens(t: TokenResponse) {
  tokens = {
    accessToken: t.access_token,
    refreshToken: t.refresh_token,
    expiresAt: Date.now() + t.expires_in * 1000,
    idToken: t.id_token ?? tokens?.idToken
  };
  store.set(K.tokens, JSON.stringify(tokens));
  notifyIdentity();
}

function clearTokens() {
  tokens = null;
  store.del(K.tokens);
  notifyIdentity();
}

// ------------------------------------------------------------------ identity from the ID Token

/** Payload of a JWT, without verifying it (see checkIdToken for why that is fine here). */
function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const [, payload] = jwt.split(".");
  const value: unknown = JSON.parse(new TextDecoder().decode(b64urlToBuf(payload ?? "")));
  if (typeof value !== "object" || value === null) throw new Error("ID Token payload is not an object");
  return value as Record<string, unknown>;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

let identityCache: { idToken?: string; identity: Identity | null } = { identity: null };
const identityListeners = new Set<() => void>();

/** Current identity; the same object is returned until the ID Token changes (useSyncExternalStore-safe). */
export function getIdentity(): Identity | null {
  const idToken = tokens?.idToken;
  if (identityCache.idToken !== idToken) {
    let identity: Identity | null = null;
    try {
      const c = idToken ? decodeJwtPayload(idToken) : null;
      const sub = c && str(c.sub);
      if (c && sub) {
        identity = { sub, name: str(c.name), preferredUsername: str(c.preferred_username), email: str(c.email), locale: str(c.locale) };
      }
    } catch {
      identity = null;
    }
    identityCache = { idToken, identity };
  }
  return identityCache.identity;
}

/** Subscribe to identity changes (sign-in, refresh with a new ID Token, sign-out). Returns unsubscribe. */
export function onIdentityChange(listener: () => void): () => void {
  identityListeners.add(listener);
  return () => identityListeners.delete(listener);
}

function notifyIdentity() {
  for (const listener of identityListeners) listener();
}

// ------------------------------------------------------------------ base64url

export const b64urlToBuf = (s: string): ArrayBuffer => {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
};

export const bufToB64url = (buf: ArrayBuffer | ArrayBufferView): string => {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const randomString = (bytes: number) => bufToB64url(crypto.getRandomValues(new Uint8Array(bytes)));

// ------------------------------------------------------------------ OAuth flow

let loginRedirect: Promise<never> | null = null;

/**
 * Redirects the browser to /oauth/authorize with a fresh PKCE pair. Single-flight: parallel callers
 * (e.g. several API calls failing at once) share one redirect instead of overwriting state/verifier.
 */
export function startLogin(): Promise<never> {
  loginRedirect ??= redirectToAuthorize();
  return loginRedirect;
}

async function redirectToAuthorize(): Promise<never> {
  const verifier = randomString(48); // 64 chars
  const challenge = bufToB64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const state = randomString(16);
  store.set(K.verifier, verifier);
  store.set(K.state, state);
  const nonce = randomString(16);
  store.set(K.nonce, nonce);
  // never come back to these (and /verify-email carries a one-time token in its URL)
  if (!["/callback", "/login", "/verify-email"].includes(location.pathname)) {
    store.set(K.returnTo, location.pathname + location.search);
  }
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: redirectUri(),
    scope: SCOPE,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    nonce
  });
  location.assign(`/oauth/authorize?${params}`);
  return new Promise<never>(() => {});
}

async function tokenRequest(body: Record<string, string>) {
  const res = await fetch("/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: CLIENT_ID, ...body })
  });
  const json = (await res.json().catch(() => ({}))) as Record<string, string>;
  if (!res.ok) throw new Error(json.error_description ?? json.error ?? `Token request failed (${res.status})`);
  return json as unknown as TokenResponse;
}

/**
 * Checks the ID Token belongs to this sign-in (OIDC Core §3.1.3.7): audience is this client and the nonce
 * is the one we sent. The signature is not re-verified here: the token came straight from the token
 * endpoint over TLS, which the spec accepts for this flow (verify with /.well-known/jwks.json elsewhere).
 */
function checkIdToken(idToken: string | undefined, expectedNonce: string | null): void {
  if (!idToken) throw new Error("Sign-in response is missing the ID Token");
  const claims = decodeJwtPayload(idToken);
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(CLIENT_ID) || !expectedNonce || claims.nonce !== expectedNonce) {
    throw new Error("Invalid sign-in response (ID Token mismatch). Please try again.");
  }
}

let callbackOnce: Promise<string> | null = null;

/** Handles /callback?code=..&state=.. — returns the path to go back to. */
export function handleCallback(): Promise<string> {
  callbackOnce ??= (async () => {
    const q = new URLSearchParams(location.search);
    if (q.get("error")) throw new Error(q.get("error_description") ?? q.get("error")!);
    const code = q.get("code");
    const state = q.get("state");
    const verifier = store.get(K.verifier);
    if (!code || !verifier || !state || state !== store.get(K.state)) {
      throw new Error("Invalid sign-in response (state mismatch). Please try again.");
    }
    const nonce = store.get(K.nonce);
    store.del(K.verifier);
    store.del(K.state);
    store.del(K.nonce);
    const tokens = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: redirectUri(), code_verifier: verifier });
    checkIdToken(tokens.id_token, nonce);
    saveTokens(tokens);
    const back = store.get(K.returnTo) ?? "/";
    store.del(K.returnTo);
    return back;
  })();
  return callbackOnce;
}

let refreshing: Promise<boolean> | null = null;

/** Single-flight refresh: rotation + reuse detection means two parallel refreshes would kill the session. */
export function refresh(): Promise<boolean> {
  if (!tokens?.refreshToken) return Promise.resolve(false);
  const rt = tokens.refreshToken;
  refreshing ??= tokenRequest({ grant_type: "refresh_token", refresh_token: rt })
    .then((t) => (saveTokens(t), true))
    .catch(() => (clearTokens(), false))
    .finally(() => (refreshing = null));
  return refreshing;
}

/** Valid access token (refreshing if it is about to expire), or null. */
export async function getAccessToken(): Promise<string | null> {
  if (!tokens) return null;
  if (Date.now() > tokens.expiresAt - 30_000 && !(await refresh())) return null;
  return tokens?.accessToken ?? null;
}

export async function logout(): Promise<void> {
  const rt = tokens?.refreshToken;
  clearTokens();
  if (rt) {
    await fetch("/oauth/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: rt, token_type_hint: "refresh_token", client_id: CLIENT_ID })
    }).catch(() => {});
  }
}

/** fetch with Bearer; on 401 refresh once and retry, otherwise restart the OAuth flow. */
export async function authFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const withAuth = (token: string | null) => {
    const headers = new Headers(init.headers);
    if (token) headers.set("Authorization", `Bearer ${token}`);
    return fetch(input, { ...init, headers });
  };
  const token = await getAccessToken();
  if (!token) return startLogin();
  let res = await withAuth(token);
  if (res.status === 401) {
    if (!(await refresh())) return startLogin();
    res = await withAuth(tokens!.accessToken);
    if (res.status === 401) {
      clearTokens();
      return startLogin();
    }
  }
  return res;
}

// ------------------------------------------------------------------ login page API (no bearer)

async function postJson<T>(path: string, body: unknown, bearer?: string): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  const res = await fetch(path, { method: "POST", headers, body: JSON.stringify(body) });
  const json = (await res.json().catch(() => ({}))) as { error?: string; error_description?: string };
  if (!res.ok) throw new Error(json.error_description ?? json.error ?? `Request failed (${res.status})`);
  return json as T;
}

/** An emailed code is waiting to be entered (returned instead of signing in). */
export interface PendingVerification {
  challengeId: string;
  /** Masked address the code went to. */
  email: string;
  reason: "register" | "verify_email" | "login";
  /** "code": type the 6 digits; "link": open the email, this page notices (emailChallengeStatus). */
  method: "code" | "link";
  expiresAt: string;
  resendAt: string;
}

/** Signed in (follow `redirect`), or enter the code from the email first. */
export type SignInStep = { redirect: string } | { verify: PendingVerification };

export interface RegisterInput {
  username: string;
  email: string;
  password: string;
  profiles: { lang: string; firstName: string; lastName: string }[];
  preferredLang?: string;
}

/** Creates the account and emails a code; entering it (confirmEmailCode with requestId) signs the user in. */
export const register = (requestId: string, input: RegisterInput) =>
  postJson<{ id: string; username: string; verification: PendingVerification }>("/auth/register", {
    ...input,
    request_id: requestId
  });

/** `identifier` is a username or an email address (an email address always needs the emailed code). */
export const loginWithPassword = (requestId: string, identifier: string, password: string) =>
  postJson<SignInStep>("/auth/login/password", { request_id: requestId, username: identifier, password });

/** Login page: confirm a sign-in code -> { redirect }. */
export const confirmSignInCode = (requestId: string, challengeId: string, code: string) =>
  postJson<{ redirect: string }>("/auth/email/verify", { request_id: requestId, challengeId, code });

/** Account page / API: confirm a code that only verifies the address. */
export const confirmEmailCode = (challengeId: string, code: string) =>
  postJson<{ verified: true }>("/auth/email/verify", { challengeId, code });

/** Account page: has the verify link been opened yet? */
export const emailChallengeStatus = (challengeId: string) =>
  postJson<{ pending: true } | { verified: true }>("/auth/email/status", { challengeId });

/**
 * Redeem an emailed link. With `requestId` (a sign-in this tab started) a sign-in link returns { redirect }
 * to /callback, so this tab gets the tokens; a verify-only link returns { verified }.
 */
export const openEmailLink = (challengeId: string, token: string, requestId?: string) =>
  postJson<{ redirect: string } | { verified: true }>("/auth/email/link", {
    challengeId,
    token,
    ...(requestId ? { request_id: requestId } : {})
  });

/**
 * A sign-in link was opened in this tab: keep it while the tab runs its own OAuth request (fresh PKCE),
 * which the login page then completes with the link (takeEmailLink). Per tab, removed when read.
 */
export function signInWithEmailLink(challengeId: string, token: string): Promise<never> {
  store.set(K.emailLink, JSON.stringify({ challengeId, token }));
  return startLogin();
}

/** Reads the link stashed by signInWithEmailLink (no side effects — safe in render). */
export function peekEmailLink(): { challengeId: string; token: string } | null {
  const raw = store.get(K.emailLink);
  try {
    return raw ? (JSON.parse(raw) as { challengeId: string; token: string }) : null;
  } catch {
    return null;
  }
}

export const clearEmailLink = () => store.del(K.emailLink);

export const resendEmailCode = (challengeId: string) => postJson<PendingVerification>("/auth/email/resend", { challengeId });

export const passkeysSupported = () => typeof window !== "undefined" && "PublicKeyCredential" in window;

interface RequestOptionsJSON {
  challenge: string;
  rpId: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
}

export async function loginWithPasskey(requestId: string): Promise<{ redirect: string }> {
  const { challengeId, publicKey } = await postJson<{ challengeId: string; publicKey: RequestOptionsJSON }>(
    "/auth/webauthn/login/options",
    { request_id: requestId }
  );
  const cred = (await navigator.credentials.get({
    publicKey: { ...publicKey, challenge: b64urlToBuf(publicKey.challenge) }
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Passkey sign-in was cancelled");
  const r = cred.response as AuthenticatorAssertionResponse;
  return postJson<{ redirect: string }>("/auth/webauthn/login/verify", {
    request_id: requestId,
    challengeId,
    credential: {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON),
        authenticatorData: bufToB64url(r.authenticatorData),
        signature: bufToB64url(r.signature),
        userHandle: r.userHandle ? bufToB64url(r.userHandle) : null
      }
    }
  });
}

interface CreationOptionsJSON {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  excludeCredentials?: { type: "public-key"; id: string; transports?: AuthenticatorTransport[] }[];
}

/** Registers a new passkey for the signed-in user. */
export async function addPasskey(name?: string): Promise<void> {
  const token = await getAccessToken();
  if (!token) return startLogin();
  const { challengeId, publicKey } = await postJson<{ challengeId: string; publicKey: CreationOptionsJSON }>(
    "/auth/webauthn/register/options",
    {},
    token
  );
  const cred = (await navigator.credentials.create({
    publicKey: {
      ...publicKey,
      challenge: b64urlToBuf(publicKey.challenge),
      user: { ...publicKey.user, id: b64urlToBuf(publicKey.user.id) },
      excludeCredentials: publicKey.excludeCredentials?.map((c) => ({ ...c, id: b64urlToBuf(c.id) }))
    }
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Passkey creation was cancelled");
  const r = cred.response as AuthenticatorAttestationResponse;
  await postJson(
    "/auth/webauthn/register/verify",
    {
      challengeId,
      name,
      credential: {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        transports: r.getTransports?.() ?? [],
        response: {
          clientDataJSON: bufToB64url(r.clientDataJSON),
          attestationObject: bufToB64url(r.attestationObject)
        }
      }
    },
    token
  );
}
