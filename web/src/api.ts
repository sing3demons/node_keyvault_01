export interface SecretSummary {
  name: string;
  enabled: boolean;
  createdOn?: string;
  updatedOn?: string;
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
  set: (name: string, value: string) => request<null>(path(name), { method: "PUT", body: JSON.stringify({ value }) }),
  remove: (name: string) => request<null>(path(name), { method: "DELETE" })
};
