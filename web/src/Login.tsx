import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  confirmSignInCode,
  emailLinkPending,
  openEmailLink,
  resumeEmailLink,
  handleCallback,
  loginWithPasskey,
  loginWithPassword,
  passkeysSupported,
  register,
  startLogin,
  type PendingVerification,
  type SignInStep
} from "./auth";
import { LANGUAGES } from "./api";
import { EmailCodeForm } from "./components";
import { LockIcon } from "./icons";

export function Shell({ title, sub, children }: { title: string; sub: string; children: React.ReactNode }) {
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
  /** Set when the server wants the code it emailed before signing in. */
  const [verify, setVerify] = useState<PendingVerification | null>(null);
  /** An emailed sign-in link was opened in this browser (VerifyEmailPage): finish it on this request. */
  const [fromLink] = useState(() => !!requestId && emailLinkPending());
  const linkRedeemed = useRef(false); // StrictMode runs effects twice; the link is single use

  // runs after render, when `run` (below) is defined
  useEffect(() => {
    if (!fromLink || !requestId || linkRedeemed.current) return;
    linkRedeemed.current = true;
    run(() => resumeEmailLink(requestId));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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

  const run = async (fn: () => Promise<SignInStep>) => {
    setBusy(true);
    setError("");
    try {
      const step = await fn();
      if ("verify" in step) {
        setVerify(step.verify);
        setPassword("");
        setConfirm("");
        setBusy(false);
        return;
      }
      location.assign(step.redirect);
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
        const { verification } = await register(requestId, {
          username,
          email,
          password,
          profiles: [{ lang, firstName, lastName }],
          preferredLang: lang
        });
        return { verify: verification };
      });
    }
    run(() => loginWithPassword(requestId, username, password));
  };

  const switchMode = (m: "signin" | "register") => {
    setMode(m);
    setError("");
  };

  if (fromLink && !error) {
    return (
      <Shell title="Signing you in…" sub="Key Vault Secrets">
        <div className="dlg-body">
          <div className="skeleton" />
        </div>
      </Shell>
    );
  }

  if (verify) {
    return (
      <Shell title={verify.reason === "login" ? "Check your email" : "Verify your email"} sub="Key Vault Secrets">
        <EmailCodeForm
          pending={verify}
          submitLabel={verify.reason === "register" ? "Verify & sign in" : "Continue"}
          cancelLabel={verify.reason === "register" ? "Sign in later" : "Use a different account"}
          onCancel={() => {
            setVerify(null);
            setMode("signin");
            setError("");
          }}
          onConfirm={async (code) => {
            try {
              const { redirect } = await confirmSignInCode(requestId, verify.challengeId, code);
              location.assign(redirect);
            } catch (e) {
              restartIfRequestExpired(e);
              throw e;
            }
          }}
        />
      </Shell>
    );
  }

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
          {mode === "signin" ? "Username or email" : "Username"}
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
            required
            minLength={3}
            maxLength={mode === "signin" ? 254 : 32}
          />
          {mode === "signin" && username.includes("@") && (
            <span className="hint">We’ll email you a code to confirm it’s you.</span>
          )}
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
            <span className="hint">
              We’ll email you a code to confirm the address. You can add your name in other languages later in Account.
            </span>
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
          {mode === "signin" ? "Sign in" : "Create account"}
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

/** The authorization request is gone (10 min) — start a fresh sign-in. */
function restartIfRequestExpired(e: unknown) {
  if (/expired or not found — please start sign-in again/i.test((e as Error).message)) {
    setTimeout(() => startLogin(), 1200);
  }
}

/**
 * /verify-email?id=…&token=…[&signin=1] — opened from the emailed link (client email_verification=link).
 * Sign-in links send the browser to the app (its initiate_login_uri), which starts a sign-in that the login
 * page completes with the link — so the user ends up signed in to that app right here. Needs a click so mail
 * scanners that open links cannot sign in on their own.
 */
export function VerifyEmailPage() {
  const q = new URLSearchParams(location.search);
  const id = q.get("id");
  const token = q.get("token");
  const signIn = q.get("signin") === "1";
  const [state, setState] = useState<"ready" | "busy" | "error" | "verified">("ready");
  const [error, setError] = useState("");

  const confirm = async () => {
    if (!id || !token) return;
    setState("busy");
    try {
      const r = await openEmailLink(id, token);
      // sign-in link: the app starts a sign-in (continue) or we are signed in already (redirect)
      if ("continue" in r) return location.assign(r.continue);
      if ("redirect" in r) return location.assign(r.redirect);
      setState("verified");
    } catch (e) {
      setError((e as Error).message);
      setState("error");
    }
  };

  if (!id || !token) {
    return (
      <Shell title="Invalid link" sub="Key Vault Secrets">
        <div className="dlg-body">
          <p>This link is incomplete. Open it straight from the email, or request a new one.</p>
        </div>
      </Shell>
    );
  }

  if (state === "verified") {
    return (
      <Shell title="Email verified" sub="Key Vault Secrets">
        <div className="dlg-body">
          <p>Your email address is confirmed. You can close this tab.</p>
        </div>
      </Shell>
    );
  }

  return (
    <Shell title={signIn ? "Sign in" : "Confirm your email"} sub="Key Vault Secrets">
      <div className="dlg-body">
        <p>{signIn ? "Continue to sign in to your account in this browser." : "Confirm that this email address is yours."}</p>
        <div className="error-text">{error}</div>
        <button className="btn-primary auth-submit" onClick={confirm} disabled={state === "busy"}>
          {state === "busy" ? (signIn ? "Signing in…" : "Confirming…") : signIn ? "Continue & sign in" : "Confirm"}
        </button>
      </div>
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
