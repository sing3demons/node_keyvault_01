export interface SecretSummary {
  name: string;
  enabled: boolean;
  createdOn?: string;
  updatedOn?: string;
  expiresOn?: string;
}

export interface GeneratedKeyPair {
  kid: string;
  privateSecretName: string;
  publicSecretName: string;
  expiresOn: string;
  jwks: { keys: Record<string, unknown>[] };
}

export interface KeyPairOptions {
  modulusLength: 2048 | 3072 | 4096;
  validDays: number;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: init?.body ? { "Content-Type": "application/json" } : undefined
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { message?: string };
    throw new Error(body.message ?? `Request failed (${response.status})`);
  }
  return (response.status === 204 ? null : await response.json()) as T;
}

const path = (name: string) => `/secrets/${encodeURIComponent(name)}`;

export const api = {
  health: () => request<{ status: string; provider: string }>("/health"),
  list: async () => (await request<{ secrets: SecretSummary[] }>("/secrets")).secrets,
  get: async (name: string) => (await request<{ value: string }>(path(name))).value,
  /** expiresOn: ISO string, or null for no expiry */
  set: (name: string, value: string, expiresOn: string | null) =>
    request<null>(path(name), { method: "PUT", body: JSON.stringify({ value, expiresOn }) }),
  remove: (name: string) => request<null>(path(name), { method: "DELETE" }),
  generateKeyPair: (name: string, options: KeyPairOptions) =>
    request<GeneratedKeyPair>(`/keypairs/${encodeURIComponent(name)}`, { method: "POST", body: JSON.stringify(options) })
};
