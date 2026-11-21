import { authFetch } from "./auth";

export interface SecretSummary {
  name: string;
  enabled: boolean;
  createdOn?: string;
  updatedOn?: string;
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
  profiles: LocalizedProfile[];
  preferredLang?: string;
  displayProfile?: LocalizedProfile;
  createdAt: string;
}

export interface AccountUpdate {
  email?: string;
  profiles?: LocalizedProfile[];
  preferredLang?: string | null;
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

export const api = {
  health: async () => (await fetch("/health")).json() as Promise<{ status: string; provider: string }>,
  me: () => request<Account>("/auth/me"),
  updateAccount: (update: AccountUpdate) =>
    request<Account>("/auth/me", { method: "PATCH", body: JSON.stringify(update) }),
  list: async () => (await request<{ secrets: SecretSummary[] }>("/secrets")).secrets,
  get: async (name: string) => (await request<{ value: string }>(path(name))).value,
  set: (name: string, value: string) => request<null>(path(name), { method: "PUT", body: JSON.stringify({ value }) }),
  remove: (name: string) => request<null>(path(name), { method: "DELETE" })
};
