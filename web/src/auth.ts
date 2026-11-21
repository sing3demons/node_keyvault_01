// OAuth2 Authorization Code + PKCE client for the SPA, plus WebAuthn (passkey) helpers.

export const CLIENT_ID = "keyvault-web";
const SCOPE = "secrets";
const redirectUri = () => `${location.origin}/callback`;

const K = {
  verifier: "oauth.pkce_verifier",
  state: "oauth.state",
  returnTo: "oauth.return_to",
  tokens: "oauth.tokens"
};

interface Tokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

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

function saveTokens(t: { access_token: string; refresh_token: string; expires_in: number }) {
  tokens = { accessToken: t.access_token, refreshToken: t.refresh_token, expiresAt: Date.now() + t.expires_in * 1000 };
  store.set(K.tokens, JSON.stringify(tokens));
}

function clearTokens() {
  tokens = null;
  store.del(K.tokens);
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

/** Redirects the browser to /oauth/authorize with a fresh PKCE pair. */
export async function startLogin(): Promise<never> {
  const verifier = randomString(48); // 64 chars
  const challenge = bufToB64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const state = randomString(16);
  store.set(K.verifier, verifier);
  store.set(K.state, state);
  if (location.pathname !== "/callback" && location.pathname !== "/login") {
    store.set(K.returnTo, location.pathname + location.search);
  }
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: redirectUri(),
    scope: SCOPE,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
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
  return json as unknown as { access_token: string; refresh_token: string; expires_in: number };
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
    store.del(K.verifier);
    store.del(K.state);
    saveTokens(await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: redirectUri(), code_verifier: verifier }));
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

export const register = (username: string, password: string) =>
  postJson<{ id: string; username: string }>("/auth/register", { username, password });

export const loginWithPassword = (requestId: string, username: string, password: string) =>
  postJson<{ redirect: string }>("/auth/login/password", { request_id: requestId, username, password });

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
