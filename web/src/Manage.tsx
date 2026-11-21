// /manage — client administration with the master credential (MASTER_CREDENTIALS), no user account needed.

import { useState, type FormEvent } from "react";
import { basicCredentials, masterClientsApi, type ClientsApi } from "./api";
import { ClientsPanel } from "./components";
import { Shell } from "./Login";

const STORE_KEY = "manage.credentials";

/** Kept per tab only (sessionStorage), so closing the tab signs out. */
const store = {
  get: () => {
    try {
      return sessionStorage.getItem(STORE_KEY);
    } catch {
      return null;
    }
  },
  set: (v: string | null) => {
    try {
      if (v) sessionStorage.setItem(STORE_KEY, v);
      else sessionStorage.removeItem(STORE_KEY);
    } catch {
      /* ignore */
    }
  }
};

export function ManagePage() {
  const [session, setSession] = useState<{ username: string; api: ClientsApi } | null>(() => {
    const saved = store.get();
    if (!saved) return null;
    try {
      return { username: atob(saved).split(":")[0] ?? "", api: masterClientsApi(saved) };
    } catch {
      return null;
    }
  });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const signIn = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    const credentials = basicCredentials(username, password);
    const clientsApi = masterClientsApi(credentials);
    try {
      await clientsApi.list(); // proves the credential
      store.set(credentials);
      setPassword("");
      setSession({ username, api: clientsApi });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const signOut = () => {
    store.set(null);
    setSession(null);
  };

  if (!session) {
    return (
      <Shell title="Manage clients" sub="Master credential">
        <form className="dlg-body" onSubmit={signIn}>
          <p className="hint">Sign in with the username and password encoded in MASTER_CREDENTIALS.</p>
          <label>
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
          </label>
          <label>
            Password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          </label>
          <div className="error-text">{error}</div>
          <button className="btn-primary auth-submit" type="submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </Shell>
    );
  }

  return (
    <div className="wrap manage-wrap">
      <div className="manage-bar">
        <span className="hint">
          Signed in as master <span className="mono">{session.username}</span>
        </span>
        <button className="btn-ghost" onClick={signOut}>
          Sign out
        </button>
      </div>
      <div className="card">
        <ClientsPanel clientsApi={session.api} />
      </div>
    </div>
  );
}
