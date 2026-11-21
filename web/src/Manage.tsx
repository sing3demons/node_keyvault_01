// /manage — client administration with the master credential (MASTER_CREDENTIALS), no user account needed.
// Sign-in: username or email + password, then the code / link emailed to the master, then a 1-hour session.

import { useMemo, useState, type FormEvent } from "react";
import { master, masterClientsApi, type MasterSession } from "./api";
import type { PendingVerification } from "./auth";
import { ClientsPanel, EmailCodeForm } from "./components";
import { Shell } from "./Login";

const STORE_KEY = "manage.session";

interface Saved {
  token: string;
  username: string;
  expiresAt: number;
}

/** Kept per tab only (sessionStorage), so closing the tab signs out. */
const store = {
  get: (): Saved | null => {
    try {
      const saved = JSON.parse(sessionStorage.getItem(STORE_KEY) ?? "null") as Saved | null;
      return saved && saved.expiresAt > Date.now() ? saved : null;
    } catch {
      return null;
    }
  },
  set: (v: Saved | null) => {
    try {
      if (v) sessionStorage.setItem(STORE_KEY, JSON.stringify(v));
      else sessionStorage.removeItem(STORE_KEY);
    } catch {
      /* ignore */
    }
  }
};

export function ManagePage() {
  const [session, setSession] = useState<Saved | null>(() => store.get());
  const [verify, setVerify] = useState<PendingVerification | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const signedIn = (s: MasterSession) => {
    const saved = { token: s.access_token, username: s.username, expiresAt: Date.now() + s.expires_in * 1000 };
    store.set(saved);
    setVerify(null);
    setSession(saved);
  };

  const end = (message = "") => {
    store.set(null);
    setSession(null);
    setVerify(null);
    setNotice(message);
  };

  const clientsApi = useMemo(
    () => session && masterClientsApi(session.token, () => end("Your master session ended (expired or the master was disabled). Sign in again.")),
    [session]
  );

  const signIn = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const { verify } = await master.login(username, password);
      setPassword("");
      setVerify(verify);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const signOut = async () => {
    if (session) await master.logout(session.token);
    end();
  };

  if (session && clientsApi) {
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
          <ClientsPanel
            clientsApi={clientsApi}
            onMasterDisabled={() =>
              end("The master credential is now disabled. Client owners manage clients from the app: sign in, then Clients.")
            }
          />
        </div>
      </div>
    );
  }

  if (verify) {
    return (
      <Shell title="Check your email" sub="Master sign-in">
        <EmailCodeForm
          pending={verify}
          submitLabel="Sign in"
          cancelLabel="Back"
          onCancel={() => setVerify(null)}
          onConfirm={async (code) => signedIn(await master.verify(verify.challengeId, code))}
          onPoll={async () => {
            const r = await master.status(verify.challengeId);
            if ("pending" in r) return false;
            signedIn(r);
            return true;
          }}
        />
      </Shell>
    );
  }

  return (
    <Shell title="Manage clients" sub="Master sign-in">
      <form className="dlg-body" onSubmit={signIn}>
        {notice ? (
          <p>{notice}</p>
        ) : (
          <p className="hint">Master username or email and password. A code (or link) is then sent to the master's email.</p>
        )}
        <label>
          Username or email
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </label>
        <div className="error-text">{error}</div>
        <button className="btn-primary auth-submit" type="submit" disabled={busy}>
          {busy ? "Checking…" : "Continue"}
        </button>
      </form>
    </Shell>
  );
}
