import { useEffect, useState, type FormEvent } from "react";
import { handleCallback, loginWithPasskey, loginWithPassword, passkeysSupported, register, startLogin } from "./auth";
import { LANGUAGES } from "./api";
import { LockIcon } from "./icons";

function Shell({ title, sub, children }: { title: string; sub: string; children: React.ReactNode }) {
  return (
    <div className="wrap auth-wrap">
      <div className="brand auth-brand">
        <div className="logo">
          <LockIcon />
        </div>
        <div>
          <h1>{title}</h1>
          <div className="sub">{sub}</div>
        </div>
      </div>
      <div className="card auth-card">{children}</div>
    </div>
  );
}

/** /login?request_id=… — the authorization server's sign-in step. */
export function LoginPage() {
  const requestId = new URLSearchParams(location.search).get("request_id");
  const [mode, setMode] = useState<"signin" | "register">("signin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [email, setEmail] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [lang, setLang] = useState<string>(LANGUAGES[0].code);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  if (!requestId) {
    return (
      <Shell title="Sign in" sub="Key Vault Secrets">
        <div className="dlg-body">
          <p>This sign-in link is incomplete or expired.</p>
          <button className="btn-primary" onClick={() => startLogin()}>
            Start sign-in
          </button>
        </div>
      </Shell>
    );
  }

  const run = async (fn: () => Promise<{ redirect: string }>) => {
    setBusy(true);
    setError("");
    try {
      const { redirect } = await fn();
      location.assign(redirect);
    } catch (e) {
      const message = (e as Error).message;
      setError(message);
      setBusy(false);
      if (/expired or not found/i.test(message)) {
        // authorization request is gone — start over transparently
        setTimeout(() => startLogin(), 1200);
      }
    }
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (mode === "register") {
      if (password !== confirm) return setError("Passwords do not match");
      return run(async () => {
        await register({ username, email, password, profiles: [{ lang, firstName, lastName }], preferredLang: lang });
        return loginWithPassword(requestId, username, password);
      });
    }
    run(() => loginWithPassword(requestId, username, password));
  };

  const switchMode = (m: "signin" | "register") => {
    setMode(m);
    setError("");
  };

  return (
    <Shell title={mode === "signin" ? "Sign in" : "Create account"} sub="Key Vault Secrets">
      <div className="tabs">
        <button className={mode === "signin" ? "active" : ""} onClick={() => switchMode("signin")} type="button">
          Sign in
        </button>
        <button className={mode === "register" ? "active" : ""} onClick={() => switchMode("register")} type="button">
          Register
        </button>
      </div>
      <form className="dlg-body" onSubmit={onSubmit}>
        <label>
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
            required
            minLength={3}
            maxLength={32}
          />
        </label>
        {mode === "register" && (
          <>
            <label>
              Email
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required />
            </label>
            <div className="name-row">
              <label>
                First name
                <input value={firstName} onChange={(e) => setFirstName(e.target.value)} autoComplete="given-name" required />
              </label>
              <label>
                Last name
                <input value={lastName} onChange={(e) => setLastName(e.target.value)} autoComplete="family-name" required />
              </label>
              <label className="lang-field">
                Language
                <select value={lang} onChange={(e) => setLang(e.target.value)}>
                  {LANGUAGES.map((l) => (
                    <option key={l.code} value={l.code}>
                      {l.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <span className="hint">You can add your name in other languages later in Account.</span>
          </>
        )}
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === "signin" ? "current-password" : "new-password"}
            required
            minLength={8}
          />
          {mode === "register" && <span className="hint">At least 8 characters</span>}
        </label>
        {mode === "register" && (
          <label>
            Confirm password
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              required
            />
          </label>
        )}
        <div className="error-text">{error}</div>
        <button className="btn-primary auth-submit" type="submit" disabled={busy}>
          {mode === "signin" ? "Sign in" : "Create account & sign in"}
        </button>
        {mode === "signin" && passkeysSupported() && (
          <>
            <div className="auth-divider">
              <span>or</span>
            </div>
            <button
              className="btn-ghost auth-submit"
              type="button"
              disabled={busy}
              onClick={() => run(() => loginWithPasskey(requestId))}
            >
              🔑 Sign in with a passkey
            </button>
          </>
        )}
      </form>
    </Shell>
  );
}

/** /callback?code=…&state=… — exchanges the code (PKCE) for tokens. */
export function CallbackPage() {
  const [error, setError] = useState("");

  useEffect(() => {
    handleCallback()
      .then((back) => location.replace(back))
      .catch((e) => setError((e as Error).message));
  }, []);

  return (
    <Shell title={error ? "Sign-in failed" : "Signing you in…"} sub="Key Vault Secrets">
      <div className="dlg-body">
        {error ? (
          <>
            <div className="error-text">{error}</div>
            <button className="btn-primary" onClick={() => startLogin()}>
              Try again
            </button>
          </>
        ) : (
          <div className="skeleton" />
        )}
      </div>
    </Shell>
  );
}
