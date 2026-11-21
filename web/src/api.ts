import { authFetch, type PendingVerification } from "./auth";

export type Permission = "read" | "write" | "delete";
export const PERMISSIONS: Permission[] = ["read", "write", "delete"];

/** What the signed-in user may do with a secret (computed by the API). */
export interface SecretAccess {
  owner: boolean;
  read: boolean;
  write: boolean;
  delete: boolean;
  share: boolean;
  /** Owner, or an admin (who cannot read the value). */
  transfer: boolean;
}

export interface AdminUser {
  id: string;
  username: string;
  email?: string;
  roles: string[];
  createdAt: string;
}

export interface SecretSummary {
  name: string;
  enabled: boolean;
  createdOn?: string;
  updatedOn?: string;
  owner: { id: string; username: string } | null;
  access: SecretAccess;
}

export interface Grant {
  user: { id: string; username: string };
  permissions: Permission[];
}

export interface LocalizedProfile {
  lang: string;
  firstName: string;
  lastName: string;
}

/** Languages the UI offers for profiles (the API accepts any BCP 47 tag). */
export const LANGUAGES = [
  { code: "th", label: "ไทย" },
  { code: "en", label: "English" }
] as const;

export interface Account {
  id: string;
  username: string;
  email?: string;
  emailVerified: boolean;
  profiles: LocalizedProfile[];
  preferredLang?: string;
  displayProfile?: LocalizedProfile;
  roles: string[];
  createdAt: string;
}

export interface AccountUpdate {
  email?: string;
  profiles?: LocalizedProfile[];
  preferredLang?: string | null;
}

export type SignInMethod = "password" | "password+email_code" | "password+email_link" | "passkey" | "registration";

export type GrantType = "authorization_code" | "refresh_token" | "client_credentials";

/** OAuth client as /admin/clients returns it (RFC 7591 metadata names + this server's extensions). */
export interface OAuthClient {
  client_id: string;
  client_name: string;
  client_id_issued_at: number;
  /** Only right after creating it / rotating the secret. */
  client_secret?: string;
  token_endpoint_auth_method: "none" | "client_secret_basic" | "client_secret_post";
  redirect_uris: string[];
  grant_types: GrantType[];
  scope: string;
  client_uri?: string;
  initiate_login_uri?: string;
  access_token_lifetime: number;
  refresh_token_lifetime: number;
  id_token_lifetime: number;
  email_verification: "code" | "link";
  updated_at: number;
}

/** What the create / edit form sends (RFC 7591 client metadata). */
export type OAuthClientInput = Omit<OAuthClient, "client_id_issued_at" | "client_secret" | "updated_at" | "client_id"> & {
  client_id?: string;
};

/** Scopes this server supports (see /.well-known/openid-configuration). */
export const SCOPES = ["openid", "profile", "email", "secrets"] as const;

/** A browser the user signed in from. */
export interface Device {
  id: string;
  name: string;
  userAgent: string;
  ip?: string;
  firstSignInAt: string;
  lastSignInAt: string;
  lastSeenAt: string;
  lastMethod: SignInMethod;
  signIns: number;
  /** Still holds a usable session. */
  active: boolean;
  /** The browser you are using now. */
  current: boolean;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await authFetch(path, {
    ...init,
    headers: init?.body ? { "Content-Type": "application/json" } : undefined
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { error?: string; error_description?: string };
    throw new Error(body.error_description ?? body.error ?? `Request failed (${response.status})`);
  }
  return (response.status === 204 ? null : await response.json()) as T;
}

const path = (name: string) => `/secrets/${encodeURIComponent(name)}`;

/** Client management calls, for either a signed-in admin (Bearer) or the master credential (Basic). */
export interface ClientsApi {
  list(): Promise<OAuthClient[]>;
  create(input: OAuthClientInput): Promise<OAuthClient>;
  update(id: string, input: OAuthClientInput): Promise<OAuthClient>;
  rotateSecret(id: string): Promise<OAuthClient>;
  remove(id: string): Promise<null>;
}

function clientsApi(send: <T>(path: string, init?: RequestInit) => Promise<T>): ClientsApi {
  const one = (id: string) => `/admin/clients/${encodeURIComponent(id)}`;
  return {
    list: async () => (await send<{ clients: OAuthClient[] }>("/admin/clients")).clients,
    create: (input) => send<OAuthClient>("/admin/clients", { method: "POST", body: JSON.stringify(input) }),
    update: (id, input) => send<OAuthClient>(one(id), { method: "PUT", body: JSON.stringify(input) }),
    rotateSecret: (id) => send<OAuthClient>(`${one(id)}/secret`, { method: "POST" }),
    remove: (id) => send<null>(one(id), { method: "DELETE" })
  };
}

/** As the signed-in admin user. */
export const userClientsApi: ClientsApi = clientsApi(request);

/** base64("username:password") (UTF-8 safe), as MASTER_CREDENTIALS and the Basic header carry it. */
export const basicCredentials = (username: string, password: string) =>
  btoa(String.fromCharCode(...new TextEncoder().encode(`${username}:${password}`)));

/** As the master credential (MASTER_CREDENTIALS), sent as HTTP Basic — no user sign-in involved. */
export function masterClientsApi(credentials: string): ClientsApi {
  return clientsApi(async <T,>(p: string, init?: RequestInit) => {
    const res = await fetch(p, {
      ...init,
      headers: { Authorization: `Basic ${credentials}`, ...(init?.body ? { "Content-Type": "application/json" } : {}) }
    });
    if (!res.ok) {
      const body = (await res.json().catch(() => ({}))) as { error?: string; error_description?: string };
      throw new Error(body.error_description ?? body.error ?? `Request failed (${res.status})`);
    }
    return (res.status === 204 ? null : await res.json()) as T;
  });
}

export const api = {
  health: async () => (await fetch("/health")).json() as Promise<{ status: string; provider: string }>,
  me: () => request<Account>("/auth/me"),
  updateAccount: (update: AccountUpdate) =>
    request<Account>("/auth/me", { method: "PATCH", body: JSON.stringify(update) }),
  startEmailVerification: () => request<PendingVerification>("/auth/me/email/verification", { method: "POST" }),
  devices: async () => (await request<{ devices: Device[] }>("/auth/me/devices")).devices,
  signOutDevice: (id: string) =>
    request<null>(`/auth/me/devices/${encodeURIComponent(id)}/sign-out`, { method: "POST" }),
  removeDevice: (id: string) => request<null>(`/auth/me/devices/${encodeURIComponent(id)}`, { method: "DELETE" }),
  list: async () => (await request<{ secrets: SecretSummary[] }>("/secrets")).secrets,
  get: async (name: string) => (await request<{ value: string }>(path(name))).value,
  set: (name: string, value: string) => request<unknown>(path(name), { method: "PUT", body: JSON.stringify({ value }) }),
  remove: (name: string) => request<null>(path(name), { method: "DELETE" }),
  grants: async (name: string) => (await request<{ grants: Grant[] }>(`${path(name)}/grants`)).grants,
  setGrant: async (name: string, username: string, permissions: Permission[]) =>
    (
      await request<{ grants: Grant[] }>(`${path(name)}/grants/${encodeURIComponent(username)}`, {
        method: "PUT",
        body: JSON.stringify({ permissions })
      })
    ).grants,
  transferOwnership: (name: string, username: string) =>
    request<{ owner: { id: string; username: string } }>(`${path(name)}/owner`, {
      method: "PUT",
      body: JSON.stringify({ username })
    }),
  adminUsers: async () => (await request<{ users: AdminUser[] }>("/admin/users")).users,
  setRoles: (username: string, roles: string[]) =>
    request<AdminUser>(`/admin/users/${encodeURIComponent(username)}/roles`, { method: "PUT", body: JSON.stringify({ roles }) }),
  removeGrant: async (name: string, username: string) =>
    (await request<{ grants: Grant[] }>(`${path(name)}/grants/${encodeURIComponent(username)}`, { method: "DELETE" })).grants
};
