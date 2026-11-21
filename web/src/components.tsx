import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  userClientsApi,
  type ClientsApi,
  type OwnersView,
  type GrantType,
  LANGUAGES,
  PERMISSIONS,
  type Account,
  type AdminUser,
  type Device,
  type Grant,
  type OAuthClient,
  type OAuthClientInput,
  type Permission,
  SCOPES,
  type SecretSummary,
  type SignInMethod
} from "./api";
import { confirmEmailCode, emailChallengeStatus, resendEmailCode, type PendingVerification } from "./auth";
import { CopyIcon, EditIcon, EyeIcon, EyeOffIcon, LockIcon, ShareIcon, TransferIcon, TrashIcon } from "./icons";

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const steps: [number, Intl.RelativeTimeFormatUnit][] = [
  [60, "second"],
  [60, "minute"],
  [24, "hour"],
  [30, "day"],
  [12, "month"],
  [Infinity, "year"]
];

export function timeAgo(iso?: string): string {
  if (!iso) return "—";
  let value = (new Date(iso).getTime() - Date.now()) / 1000;
  for (const [size, unit] of steps) {
    if (Math.abs(value) < size) return rtf.format(Math.round(value), unit);
    value /= size;
  }
  return "";
}

/* ---------- modal built on <dialog> ---------- */

function Modal({ open, onClose, children }: { open: boolean; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);
  return (
    <dialog ref={ref} onClose={onClose} onClick={(e) => e.target === ref.current && onClose()}>
      {open && children}
    </dialog>
  );
}

/* ---------- emailed one-time code ---------- */

interface CodeFormProps {
  pending: PendingVerification;
  submitLabel: string;
  /** Code method. Throw to show an error; resolve when done. */
  onConfirm: (code: string) => Promise<void>;
  /**
   * Link method, when this page should notice the link being opened (account page): called every 2s;
   * resolve true once handled, throw to stop with an error. Without it (sign-in), the link signs the user
   * in wherever it is opened.
   */
  onPoll?: () => Promise<boolean>;
  onCancel?: () => void;
  cancelLabel?: string;
}

/**
 * "Enter the 6-digit code we sent to s•••@example.com" — or, for links, "open the link we sent" while
 * polling — with a resend button that honours the cooldown.
 */
export function EmailCodeForm({ pending: initial, submitLabel, onConfirm, onPoll, onCancel, cancelLabel = "Back" }: CodeFormProps) {
  /** sentKey: bumped on resend so polling restarts even though the challenge id stays the same. */
  const [pending, setPending] = useState<PendingVerification & { sentKey?: number }>(initial);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const wait = Math.max(0, Math.ceil((new Date(pending.resendAt).getTime() - now) / 1000));
  const isLink = pending.method === "link";
  const pollRef = useRef(onPoll);
  pollRef.current = onPoll;
  const [pollError, setPollError] = useState("");

  // link method: wait for the link to be opened (in any browser / device)
  useEffect(() => {
    if (!isLink || !pollRef.current) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        if (await pollRef.current?.()) return;
      } catch (e) {
        if (!stopped) setPollError((e as Error).message);
        return;
      }
      if (!stopped) timer = setTimeout(tick, 2000);
    };
    timer = setTimeout(tick, 2000);
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [isLink, pending.challengeId, pending.sentKey]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onConfirm(code);
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  const resend = async () => {
    setError("");
    setNotice("");
    try {
      setPending({ ...(await resendEmailCode(pending.challengeId)), sentKey: Date.now() });
      setCode("");
      setPollError("");
      setNotice(isLink ? "A new link is on its way — the previous one no longer works." : "A new code is on its way.");
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const actions = (
    <div className="code-actions">
      <button type="button" className="btn-ghost" onClick={resend} disabled={busy || wait > 0}>
        {wait > 0 ? `Resend ${isLink ? "link" : "code"} (${wait}s)` : `Resend ${isLink ? "link" : "code"}`}
      </button>
      {onCancel && (
        <button type="button" className="btn-ghost" onClick={onCancel} disabled={busy}>
          {cancelLabel}
        </button>
      )}
    </div>
  );

  if (isLink) {
    return (
      <div className="dlg-body">
        {onPoll ? (
          <p>
            We sent a link to <strong>{pending.email}</strong>. Open it — on this or any other device — to{" "}
            {pending.reason === "login" ? "finish signing in here" : "confirm your email address"}.
          </p>
        ) : (
          <p>
            We sent a link to <strong>{pending.email}</strong>. Open it to {pending.reason === "login" ? "finish signing in" : "confirm your email and sign in"}{" "}
            — you will be signed in in the browser where you open it, so you can close this tab.
          </p>
        )}
        {onPoll && !pollError && (
          <div className="waiting">
            <span className="spinner" /> Waiting for you to open the link…
          </div>
        )}
        <span className="hint">The link expires {timeAgo(pending.expiresAt)}. Check your spam folder if it has not arrived.</span>
        <div className="error-text">{error || pollError}</div>
        {notice && !error && !pollError && <div className="hint">{notice}</div>}
        {actions}
      </div>
    );
  }

  return (
    <form className="dlg-body" onSubmit={submit}>
      <p>
        {pending.reason === "login" ? "To finish signing in, enter" : "To confirm your email address, enter"} the 6-digit code
        we sent to <strong>{pending.email}</strong>.
      </p>
      <label>
        Code
        <input
          className="code-input"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/[^\d]/g, "").slice(0, 6))}
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="\d{6}"
          maxLength={6}
          autoFocus
          required
        />
        <span className="hint">Expires {timeAgo(pending.expiresAt)}. Check your spam folder if it has not arrived.</span>
      </label>
      <div className="error-text">{error}</div>
      {notice && !error && <div className="hint">{notice}</div>}
      <button className="btn-primary auth-submit" type="submit" disabled={busy || code.length !== 6}>
        {busy ? "Checking…" : submitLabel}
      </button>
      {actions}
    </form>
  );
}

/* ---------- secret row ---------- */

interface RowProps {
  secret: SecretSummary;
  onEdit: () => void;
  onDelete: () => void;
  onShare: () => void;
  onTransfer: () => void;
  onError: (message: string) => void;
  onCopied: () => void;
}

export function SecretRow({ secret, onEdit, onDelete, onShare, onTransfer, onError, onCopied }: RowProps) {
  const { access } = secret;
  const [value, setValue] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // hide value again whenever the secret is updated
  useEffect(() => setValue(null), [secret.updatedOn]);

  const withValue = async (fn: (v: string) => void | Promise<void>) => {
    try {
      setBusy(true);
      await fn(value ?? (await api.get(secret.name)));
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="row">
      <div className="row-main">
        <div className="name mono" title={secret.name}>
          {secret.name}
          {!secret.enabled && <span className="badge">disabled</span>}
        </div>
        <div className="meta" title={secret.updatedOn && new Date(secret.updatedOn).toLocaleString()}>
          Updated {timeAgo(secret.updatedOn)} · {access.owner ? "owned by you" : `owner @${secret.owner?.username ?? "unknown"}`}
          {!access.owner && (access.read || access.write || access.delete) && <span className="badge">shared with you</span>}
        </div>
      </div>

      <div className="value mono">
        {access.read ? (
          <>
            {value === null ? <span className="masked">••••••••••••</span> : <span title={value}>{value}</span>}
            <button
              className="icon-btn"
              disabled={busy}
              title={value === null ? "Show value" : "Hide value"}
              onClick={() => (value === null ? withValue(setValue) : setValue(null))}
            >
              {value === null ? <EyeIcon /> : <EyeOffIcon />}
            </button>
          </>
        ) : (
          <span className="masked locked" title="Only the owner, or people they share it with, can see the value">
            <LockIcon /> no access
          </span>
        )}
      </div>

      <div className="actions">
        {access.read && (
          <button
            className="icon-btn"
            disabled={busy}
            title="Copy value"
            onClick={() =>
              withValue(async (v) => {
                await navigator.clipboard.writeText(v);
                onCopied();
              })
            }
          >
            <CopyIcon />
          </button>
        )}
        {access.write && (
          <button className="icon-btn" title="Edit" onClick={onEdit}>
            <EditIcon />
          </button>
        )}
        {access.share && (
          <button className="icon-btn" title="Share" onClick={onShare}>
            <ShareIcon />
          </button>
        )}
        {access.transfer && (
          <button className="icon-btn" title={access.owner ? "Transfer ownership" : "Transfer ownership (admin)"} onClick={onTransfer}>
            <TransferIcon />
          </button>
        )}
        {access.delete && (
          <button className="icon-btn danger" title="Delete" onClick={onDelete}>
            <TrashIcon />
          </button>
        )}
      </div>
    </div>
  );
}

/* ---------- create / edit dialog ---------- */

interface EditProps {
  open: boolean;
  /** name of the secret being edited; null = create */
  editing: string | null;
  /** false when the user may overwrite but not read the current value */
  canRead?: boolean;
  existingNames: string[];
  onClose: () => void;
  onSaved: (name: string, created: boolean) => void;
}

export function EditDialog({ open, editing, canRead = true, existingNames, onClose, onSaved }: EditProps) {
  return (
    <Modal open={open} onClose={onClose}>
      <EditForm editing={editing} canRead={canRead} existingNames={existingNames} onClose={onClose} onSaved={onSaved} />
    </Modal>
  );
}

function EditForm({ editing, canRead = true, existingNames, onClose, onSaved }: Omit<EditProps, "open">) {
  const [name, setName] = useState(editing ?? "");
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(!!editing && canRead);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!editing || !canRead) return;
    api
      .get(editing)
      .then(setValue)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [editing, canRead]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const trimmed = name.trim();
    if (!editing && existingNames.some((n) => n.toLowerCase() === trimmed.toLowerCase())) {
      setError(`"${trimmed}" already exists — edit it instead.`);
      return;
    }
    setSaving(true);
    setError("");
    try {
      await api.set(trimmed, value);
      onSaved(trimmed, !editing);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <div className="dlg-body">
        <h2>{editing ? "Edit secret" : "New secret"}</h2>
        <label>
          Name
          <input
            className="mono"
            value={name}
            onChange={(e) => setName(e.target.value)}
            readOnly={!!editing}
            autoFocus={!editing}
            required
            maxLength={127}
            pattern="[0-9A-Za-z\-]+"
            placeholder="my-api-key"
            autoComplete="off"
          />
          <span className="hint">Letters, numbers and dashes only (Key Vault rule)</span>
        </label>
        <label>
          Value
          <textarea
            className="mono"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            autoFocus={!!editing}
            required
            disabled={loading}
            placeholder={loading ? "Loading…" : editing && !canRead ? "Current value is hidden — enter a new value" : "secret value"}
          />
        </label>
        <div className="error-text">{error}</div>
      </div>
      <div className="dlg-foot">
        <button type="button" className="btn-ghost" onClick={onClose}>
          Cancel
        </button>
        <button type="submit" className="btn-primary" disabled={saving || loading}>
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </form>
  );
}

/* ---------- delete confirm ---------- */

interface ConfirmProps {
  name: string | null;
  onClose: () => void;
  onDeleted: (name: string) => void;
  onError: (message: string) => void;
}

export function DeleteDialog({ name, onClose, onDeleted, onError }: ConfirmProps) {
  const [deleting, setDeleting] = useState(false);

  const confirm = async () => {
    if (!name) return;
    setDeleting(true);
    try {
      await api.remove(name);
      onDeleted(name);
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <Modal open={name !== null} onClose={onClose}>
      <div className="dlg-body">
        <h2>Delete secret?</h2>
        <p>
          <strong className="mono">{name}</strong> will be soft-deleted. Creating a secret with the same name later
          recovers it.
        </p>
      </div>
      <div className="dlg-foot">
        <button type="button" className="btn-ghost" onClick={onClose}>
          Cancel
        </button>
        <button type="button" className="btn-danger" disabled={deleting} onClick={confirm}>
          {deleting ? "Deleting…" : "Delete"}
        </button>
      </div>
    </Modal>
  );
}

/* ---------- toasts ---------- */

export interface Toast {
  id: number;
  message: string;
  error?: boolean;
}

export function Toasts({ items }: { items: Toast[] }) {
  return (
    <div className="toasts" role="status">
      {items.map((t) => (
        <div key={t.id} className={`toast${t.error ? " err" : ""}`}>
          {t.message}
        </div>
      ))}
    </div>
  );
}

/* ---------- account (email, per-language profiles, preferred language) ---------- */

interface AccountProps {
  account: Account | null;
  open: boolean;
  onClose: () => void;
  onSaved: (account: Account) => void;
  /** The email was verified (dialog stays open). */
  onVerified: (account: Account) => void;
}

export function AccountDialog({ account, open, onClose, onSaved, onVerified }: AccountProps) {
  const [verifying, setVerifying] = useState<PendingVerification | null>(null);
  const close = () => {
    setVerifying(null);
    onClose();
  };
  return (
    <Modal open={open && !!account} onClose={close}>
      {account &&
        (verifying ? (
          <div>
            <div className="dlg-body">
              <h2>Verify email</h2>
            </div>
            <EmailCodeForm
              pending={verifying}
              submitLabel="Verify"
              cancelLabel="Cancel"
              onCancel={() => setVerifying(null)}
              onConfirm={async (code) => {
                await confirmEmailCode(verifying.challengeId, code);
                setVerifying(null);
                onVerified(await api.me());
              }}
              onPoll={async () => {
                if ("pending" in (await emailChallengeStatus(verifying.challengeId))) return false;
                setVerifying(null);
                onVerified(await api.me());
                return true;
              }}
            />
          </div>
        ) : (
          <AccountForm key={account.id} account={account} onClose={close} onSaved={onSaved} onVerify={setVerifying} />
        ))}
    </Modal>
  );
}

type ProfileDraft = { lang: string; label: string; firstName: string; lastName: string };

function AccountForm({
  account,
  onClose,
  onSaved,
  onVerify
}: { account: Account; onVerify: (pending: PendingVerification) => void } & Pick<AccountProps, "onClose" | "onSaved">) {
  // one row per UI language, plus any other language the API already has
  const initial: ProfileDraft[] = [
    ...LANGUAGES.map(({ code, label }) => {
      const p = account.profiles.find((x) => x.lang === code);
      return { lang: code, label, firstName: p?.firstName ?? "", lastName: p?.lastName ?? "" };
    }),
    ...account.profiles
      .filter((p) => !LANGUAGES.some((l) => l.code === p.lang))
      .map((p) => ({ lang: p.lang, label: p.lang, firstName: p.firstName, lastName: p.lastName }))
  ];
  const [email, setEmail] = useState(account.email ?? "");
  const [rows, setRows] = useState(initial);
  const [preferred, setPreferred] = useState(account.preferredLang ?? "");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [sending, setSending] = useState(false);
  const emailUnchanged = email.trim().toLowerCase() === (account.email ?? "");

  const sendCode = async () => {
    setSending(true);
    setError("");
    try {
      onVerify(await api.startEmailVerification());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSending(false);
    }
  };

  const filled = rows.filter((r) => r.firstName.trim() && r.lastName.trim());
  const setRow = (lang: string, field: "firstName" | "lastName", value: string) =>
    setRows((list) => list.map((r) => (r.lang === lang ? { ...r, [field]: value } : r)));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const partial = rows.find((r) => !!r.firstName.trim() !== !!r.lastName.trim());
    if (partial) return setError(`Fill both first and last name for ${partial.label}, or leave both empty.`);
    if (filled.length === 0) return setError("Add your name in at least one language.");
    setSaving(true);
    setError("");
    try {
      const profiles = filled.map(({ lang, firstName, lastName }) => ({ lang, firstName, lastName }));
      const keepPreferred = filled.some((r) => r.lang === preferred);
      onSaved(
        await api.updateAccount({
          ...(email.trim() ? { email: email.trim() } : {}),
          profiles,
          preferredLang: keepPreferred ? preferred : null
        })
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <div className="dlg-body">
        <h2>Account</h2>
        <label>
          <span>
            Email
            {account.email && emailUnchanged && (
              <span className={`badge ${account.emailVerified ? "badge-ok" : "badge-warn"}`}>
                {account.emailVerified ? "Verified" : "Not verified"}
              </span>
            )}
          </span>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
          {!emailUnchanged && email.trim() && (
            <span className="hint">After saving you will need to verify the new address.</span>
          )}
        </label>
        {account.email && emailUnchanged && !account.emailVerified && (
          <button type="button" className="btn-ghost" onClick={sendCode} disabled={sending}>
            {sending ? "Sending…" : "Send verification code"}
          </button>
        )}
        {rows.map((r) => (
          <div className="name-row" key={r.lang}>
            <label>
              First name · {r.label}
              <input value={r.firstName} onChange={(e) => setRow(r.lang, "firstName", e.target.value)} />
            </label>
            <label>
              Last name · {r.label}
              <input value={r.lastName} onChange={(e) => setRow(r.lang, "lastName", e.target.value)} />
            </label>
          </div>
        ))}
        <label>
          Show my name in
          <select value={filled.some((r) => r.lang === preferred) ? preferred : ""} onChange={(e) => setPreferred(e.target.value)}>
            <option value="">Default (first available)</option>
            {filled.map((r) => (
              <option key={r.lang} value={r.lang}>
                {r.label}
              </option>
            ))}
          </select>
          <span className="hint">Only languages you have filled in can be chosen.</span>
        </label>
        <div className="error-text">{error}</div>
      </div>
      <div className="dlg-foot">
        <button type="button" className="btn-ghost" onClick={onClose}>
          Cancel
        </button>
        <button type="submit" className="btn-primary" disabled={saving}>
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </form>
  );
}

/* ---------- share (owner grants read / write / delete) ---------- */

const PERMISSION_LABELS: Record<Permission, string> = { read: "View", write: "Edit", delete: "Delete" };

interface ShareProps {
  name: string | null;
  onClose: () => void;
  onError: (message: string) => void;
}

export function ShareDialog({ name, onClose, onError }: ShareProps) {
  return (
    <Modal open={name !== null} onClose={onClose}>
      {name && <ShareForm key={name} name={name} onClose={onClose} onError={onError} />}
    </Modal>
  );
}

function ShareForm({ name, onClose, onError }: { name: string } & Omit<ShareProps, "name">) {
  const [grants, setGrants] = useState<Grant[] | null>(null);
  const [username, setUsername] = useState("");
  const [newPerms, setNewPerms] = useState<Permission[]>(["read"]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .grants(name)
      .then(setGrants)
      .catch((e: Error) => onError(e.message));
  }, [name, onError]);

  const run = async (fn: () => Promise<Grant[]>) => {
    setBusy(true);
    setError("");
    try {
      setGrants(await fn());
      return true;
    } catch (e) {
      setError((e as Error).message);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const toggle = (list: Permission[], p: Permission) => (list.includes(p) ? list.filter((x) => x !== p) : [...list, p]);

  const add = async (event: FormEvent) => {
    event.preventDefault();
    if (newPerms.length === 0) return setError("Pick at least one permission.");
    if (await run(() => api.setGrant(name, username.trim(), newPerms))) {
      setUsername("");
      setNewPerms(["read"]);
    }
  };

  return (
    <form onSubmit={add}>
      <div className="dlg-body">
        <h2>
          Share <span className="mono">{name}</span>
        </h2>
        <p className="hint">Everyone signed in can see this secret's name. Only people listed here can do more.</p>
        {grants === null ? (
          <div className="skeleton" />
        ) : grants.length === 0 ? (
          <p className="hint">Not shared with anyone yet.</p>
        ) : (
          <div className="grant-list">
            {grants.map((g) => (
              <div className="grant-row" key={g.user.id}>
                <span className="mono">@{g.user.username}</span>
                {PERMISSIONS.map((p) => (
                  <label className="check" key={p}>
                    <input
                      type="checkbox"
                      checked={g.permissions.includes(p)}
                      disabled={busy}
                      onChange={() => run(() => api.setGrant(name, g.user.username, toggle(g.permissions, p)))}
                    />
                    {PERMISSION_LABELS[p]}
                  </label>
                ))}
                <button
                  type="button"
                  className="icon-btn danger"
                  title="Remove access"
                  disabled={busy}
                  onClick={() => run(() => api.removeGrant(name, g.user.username))}
                >
                  <TrashIcon />
                </button>
              </div>
            ))}
          </div>
        )}
        <div className="grant-row add">
          <input placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          {PERMISSIONS.map((p) => (
            <label className="check" key={p}>
              <input type="checkbox" checked={newPerms.includes(p)} onChange={() => setNewPerms((l) => toggle(l, p))} />
              {PERMISSION_LABELS[p]}
            </label>
          ))}
          <button type="submit" className="btn-primary" disabled={busy || !username.trim()}>
            Add
          </button>
        </div>
        <div className="error-text">{error}</div>
      </div>
      <div className="dlg-foot">
        <button type="button" className="btn-ghost" onClick={onClose}>
          Done
        </button>
      </div>
    </form>
  );
}

/* ---------- transfer ownership (owner, or admin) ---------- */

interface TransferProps {
  secret: SecretSummary | null;
  onClose: () => void;
  onTransferred: (name: string, newOwner: string) => void;
}

export function TransferDialog({ secret, onClose, onTransferred }: TransferProps) {
  return (
    <Modal open={secret !== null} onClose={onClose}>
      {secret && <TransferForm key={secret.name} secret={secret} onClose={onClose} onTransferred={onTransferred} />}
    </Modal>
  );
}

function TransferForm({ secret, onClose, onTransferred }: { secret: SecretSummary } & Omit<TransferProps, "secret">) {
  const [username, setUsername] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const { owner } = await api.transferOwnership(secret.name, username.trim());
      onTransferred(secret.name, owner.username);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <div className="dlg-body">
        <h2>
          Transfer <span className="mono">{secret.name}</span>
        </h2>
        <p className="hint">
          Current owner: @{secret.owner?.username ?? "unknown"}.{" "}
          {secret.access.owner
            ? "You will lose all access unless the new owner shares it back."
            : "As an admin you can reassign the owner, but you still cannot see the value."}
        </p>
        <label>
          New owner (username)
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus required />
        </label>
        <div className="error-text">{error}</div>
      </div>
      <div className="dlg-foot">
        <button type="button" className="btn-ghost" onClick={onClose}>
          Cancel
        </button>
        <button type="submit" className="btn-primary" disabled={busy || !username.trim()}>
          {busy ? "Transferring…" : "Transfer"}
        </button>
      </div>
    </form>
  );
}

/* ---------- users & roles (admin) ---------- */

export function UsersDialog({ open, currentUserId, onClose }: { open: boolean; currentUserId?: string; onClose: () => void }) {
  return (
    <Modal open={open} onClose={onClose}>
      {open && <UsersPanel currentUserId={currentUserId} onClose={onClose} />}
    </Modal>
  );
}

function UsersPanel({ currentUserId, onClose }: { currentUserId?: string; onClose: () => void }) {
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    api
      .adminUsers()
      .then(setUsers)
      .catch((e: Error) => setError(e.message));
  }, []);

  const toggleAdmin = async (u: AdminUser) => {
    const roles = u.roles.includes("admin") ? u.roles.filter((r) => r !== "admin") : [...u.roles, "admin"];
    setBusy(u.id);
    setError("");
    try {
      const updated = await api.setRoles(u.username, roles);
      setUsers((list) => list?.map((x) => (x.id === u.id ? updated : x)) ?? null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div>
      <div className="dlg-body">
        <h2>Users</h2>
        <p className="hint">Admins can transfer ownership of any secret. They cannot read values they were not given.</p>
        {users === null ? (
          <div className="skeleton" />
        ) : (
          <div className="grant-list">
            {users.map((u) => (
              <div className="grant-row" key={u.id}>
                <span className="mono">@{u.username}</span>
                <span className="hint">{u.email ?? ""}</span>
                <label className="check push-right">
                  <input type="checkbox" checked={u.roles.includes("admin")} disabled={busy !== null} onChange={() => toggleAdmin(u)} />
                  Admin{u.id === currentUserId ? " (you)" : ""}
                </label>
                {u.roles.includes("client_admin") && <span className="badge">Client owner</span>}
              </div>
            ))}
          </div>
        )}
        <div className="error-text">{error}</div>
      </div>
      <div className="dlg-foot">
        <button type="button" className="btn-ghost" onClick={onClose}>
          Done
        </button>
      </div>
    </div>
  );
}

/* ---------- devices the user signed in from ---------- */

const METHOD_LABELS: Record<SignInMethod, string> = {
  password: "Password",
  "password+email_code": "Password + email code",
  "password+email_link": "Password + email link",
  passkey: "Passkey",
  registration: "Registration"
};

export function DevicesDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Modal open={open} onClose={onClose}>
      {open && <DevicesPanel onClose={onClose} />}
    </Modal>
  );
}

function DevicesPanel({ onClose }: { onClose: () => void }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const load = () =>
    api
      .devices()
      .then(setDevices)
      .catch((e: Error) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  const act = async (d: Device, action: "signOut" | "remove") => {
    if (action === "remove" && !confirm(`Sign out “${d.name}” and remove it from this list?`)) return;
    setBusy(d.id);
    setError("");
    try {
      if (action === "signOut") await api.signOutDevice(d.id);
      else await api.removeDevice(d.id);
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div>
      <div className="dlg-body">
        <h2>Devices</h2>
        <p className="hint">Browsers that have signed in to your account. Don’t recognize one? Sign it out and change your password.</p>
        {devices === null ? (
          <div className="skeleton" />
        ) : devices.length === 0 ? (
          <p className="hint">No sign-ins recorded yet.</p>
        ) : (
          <div className="device-list">
            {devices.map((d) => (
              <div className="device-row" key={d.id}>
                <div className="device-main">
                  <div>
                    <strong>{d.name}</strong>
                    {d.current ? (
                      <span className="badge badge-ok">This device</span>
                    ) : d.active ? (
                      <span className="badge">Signed in</span>
                    ) : (
                      <span className="badge">Signed out</span>
                    )}
                  </div>
                  <div className="hint" title={d.userAgent}>
                    Last active {timeAgo(d.lastSeenAt)}
                    {d.ip ? ` · ${d.ip}` : ""} · {METHOD_LABELS[d.lastMethod] ?? d.lastMethod}
                  </div>
                  <div className="hint">
                    First sign-in {new Date(d.firstSignInAt).toLocaleString()} · {d.signIns} sign-in{d.signIns === 1 ? "" : "s"}
                  </div>
                </div>
                {!d.current && (
                  <div className="device-actions">
                    {d.active && (
                      <button className="btn-ghost" disabled={busy !== null} onClick={() => act(d, "signOut")}>
                        Sign out
                      </button>
                    )}
                    <button className="btn-ghost" disabled={busy !== null} onClick={() => act(d, "remove")} title="Sign out and forget">
                      <TrashIcon />
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
        <div className="error-text">{error}</div>
      </div>
      <div className="dlg-foot">
        <button type="button" className="btn-ghost" onClick={onClose}>
          Done
        </button>
      </div>
    </div>
  );
}

/* ---------- OAuth clients (admin) ---------- */

const AUTH_METHOD_LABELS: Record<OAuthClient["token_endpoint_auth_method"], string> = {
  none: "Public (PKCE, no secret)",
  client_secret_basic: "Confidential — secret via HTTP Basic",
  client_secret_post: "Confidential — secret in form body"
};

const BLANK_CLIENT: OAuthClientInput = {
  client_name: "",
  token_endpoint_auth_method: "client_secret_basic",
  redirect_uris: [],
  grant_types: ["authorization_code", "refresh_token"],
  scope: "openid profile email",
  access_token_lifetime: 900,
  refresh_token_lifetime: 2_592_000,
  id_token_lifetime: 900,
  email_verification: "code"
};

export function ClientsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Modal open={open} onClose={onClose}>
      {open && <ClientsPanel clientsApi={userClientsApi} onClose={onClose} />}
    </Modal>
  );
}

/** Client administration: the clients, and who owns their management. */
export function ClientsPanel({
  clientsApi,
  onClose,
  onMasterDisabled
}: {
  clientsApi: ClientsApi;
  onClose?: () => void;
  /** The master disabled itself: its session is over. */
  onMasterDisabled?: () => void;
}) {
  const [tab, setTab] = useState<"clients" | "owners">("clients");
  return (
    <div>
      <div className="tabs">
        <button type="button" className={tab === "clients" ? "active" : ""} onClick={() => setTab("clients")}>
          Clients
        </button>
        <button type="button" className={tab === "owners" ? "active" : ""} onClick={() => setTab("owners")}>
          Owners
        </button>
      </div>
      {tab === "clients" ? (
        <ClientList clientsApi={clientsApi} onClose={onClose} />
      ) : (
        <OwnersPanel clientsApi={clientsApi} onClose={onClose} onMasterDisabled={onMasterDisabled} />
      )}
    </div>
  );
}

/** List / create / edit / rotate / delete clients, through `clientsApi` (owner or master credential). */
function ClientList({ clientsApi, onClose }: { clientsApi: ClientsApi; onClose?: () => void }) {
  const [clients, setClients] = useState<OAuthClient[] | null>(null);
  const [defaultMailFrom, setDefaultMailFrom] = useState("");
  const [editing, setEditing] = useState<OAuthClient | "new" | null>(null);
  /** Secret just issued: shown once. */
  const [secret, setSecret] = useState<{ clientId: string; value: string } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () =>
    clientsApi
      .list()
      .then((r) => {
        setClients(r.clients);
        setDefaultMailFrom(r.defaultMailFrom);
      })
      .catch((e: Error) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  const saved = (c: OAuthClient) => {
    setEditing(null);
    if (c.client_secret) setSecret({ clientId: c.client_id, value: c.client_secret });
    load();
  };

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (editing) {
    return (
      <ClientForm
        client={editing === "new" ? null : editing}
        clientsApi={clientsApi}
        defaultMailFrom={defaultMailFrom}
        onCancel={() => setEditing(null)}
        onSaved={saved}
      />
    );
  }

  return (
    <div>
      <div className="dlg-body">
        <h2>OAuth clients</h2>
        <p className="hint">
          Apps that may sign users in here (OAuth 2.0 / OpenID Connect). Each one has its own redirect URIs, token lifetimes
          and email verification method.
        </p>
        {secret && (
          <div className="secret-once">
            <strong>Client secret for {secret.clientId}</strong>
            <span className="hint">Copy it now — it is not shown again.</span>
            <div className="secret-once-row">
              <code className="mono">{secret.value}</code>
              <button type="button" className="btn-ghost" onClick={() => navigator.clipboard.writeText(secret.value)} title="Copy">
                <CopyIcon />
              </button>
            </div>
          </div>
        )}
        {clients === null ? (
          <div className="skeleton" />
        ) : (
          <div className="device-list">
            {clients.map((c) => (
              <div className="device-row" key={c.client_id}>
                <div className="device-main">
                  <div>
                    <strong>{c.client_name}</strong>
                    <span className="badge">{c.token_endpoint_auth_method === "none" ? "Public" : "Confidential"}</span>
                    {c.grant_types.includes("authorization_code") && (
                      <span className="badge">Email {c.email_verification === "link" ? "link" : "code"}</span>
                    )}
                    {c.grant_types.includes("client_credentials") && <span className="badge">Client credentials</span>}
                  </div>
                  <div className="hint mono">{c.client_id}</div>
                  {c.redirect_uris.length > 0 && <div className="hint">{c.redirect_uris.join(" · ")}</div>}
                  {c.grant_types.includes("authorization_code") && (
                    <div className="hint">
                      Emails from {c.mail_from ?? defaultMailFrom}
                      {!c.mail_from && " (server default)"}
                    </div>
                  )}
                </div>
                <div className="device-actions">
                  <button className="btn-ghost" disabled={busy} onClick={() => setEditing(c)} title="Edit">
                    <EditIcon />
                  </button>
                  {c.token_endpoint_auth_method !== "none" && (
                    <button
                      className="btn-ghost"
                      disabled={busy}
                      title="New client secret"
                      onClick={() =>
                        confirm(`Issue a new secret for “${c.client_name}”? The current one stops working immediately.`) &&
                        act(async () => {
                          const r = await clientsApi.rotateSecret(c.client_id);
                          if (r.client_secret) setSecret({ clientId: r.client_id, value: r.client_secret });
                        })
                      }
                    >
                      🔑
                    </button>
                  )}
                  <button
                    className="btn-ghost"
                    disabled={busy}
                    title="Delete (also revokes its tokens)"
                    onClick={() =>
                      confirm(`Delete “${c.client_name}”? Everyone signed in to it is signed out.`) &&
                      act(() => clientsApi.remove(c.client_id))
                    }
                  >
                    <TrashIcon />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="error-text">{error}</div>
      </div>
      <div className="dlg-foot">
        {onClose && (
          <button type="button" className="btn-ghost" onClick={onClose}>
            Done
          </button>
        )}
        <button type="button" className="btn-primary" onClick={() => { setSecret(null); setEditing("new"); }}>
          New client
        </button>
      </div>
    </div>
  );
}

function ClientForm({
  client,
  clientsApi,
  defaultMailFrom,
  onCancel,
  onSaved
}: {
  client: OAuthClient | null;
  clientsApi: ClientsApi;
  /** MAIL_FROM, used when the sender field is left empty. */
  defaultMailFrom: string;
  onCancel: () => void;
  onSaved: (c: OAuthClient) => void;
}) {
  const start = client ?? BLANK_CLIENT;
  const [clientId, setClientId] = useState("");
  const [name, setName] = useState(start.client_name);
  const [authMethod, setAuthMethod] = useState(start.token_endpoint_auth_method);
  const [redirects, setRedirects] = useState(start.redirect_uris.join("\n"));
  const [scopes, setScopes] = useState(new Set(start.scope.split(" ").filter(Boolean)));
  const [grants, setGrants] = useState(new Set<GrantType>(start.grant_types));
  const toggleGrant = (g: GrantType) =>
    setGrants((set) => {
      const next = new Set(set);
      if (next.has(g)) next.delete(g);
      else next.add(g);
      if (g === "authorization_code" && !next.has(g)) next.delete("refresh_token"); // refresh needs the code grant
      return next;
    });
  const userSignIn = grants.has("authorization_code");
  const [initiate, setInitiate] = useState(start.initiate_login_uri ?? "");
  const [homepage, setHomepage] = useState(start.client_uri ?? "");
  const [emailMethod, setEmailMethod] = useState(start.email_verification);
  const [mailFrom, setMailFrom] = useState(start.mail_from ?? "");
  const [accessTtl, setAccessTtl] = useState(String(start.access_token_lifetime));
  const [refreshTtl, setRefreshTtl] = useState(String(start.refresh_token_lifetime));
  const [idTtl, setIdTtl] = useState(String(start.id_token_lifetime));
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const toggleScope = (s: string) =>
    setScopes((set) => {
      const next = new Set(set);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    const input: OAuthClientInput = {
      ...(client ? { client_id: client.client_id } : clientId.trim() ? { client_id: clientId.trim() } : {}),
      client_name: name.trim(),
      token_endpoint_auth_method: authMethod,
      redirect_uris: userSignIn ? redirects.split(/\s+/).filter(Boolean) : [],
      grant_types: [...grants],
      scope: [...scopes].join(" "),
      ...(initiate.trim() ? { initiate_login_uri: initiate.trim() } : {}),
      ...(homepage.trim() ? { client_uri: homepage.trim() } : {}),
      access_token_lifetime: Number(accessTtl),
      refresh_token_lifetime: Number(refreshTtl),
      id_token_lifetime: Number(idTtl),
      email_verification: emailMethod,
      ...(mailFrom.trim() ? { mail_from: mailFrom.trim() } : {})
    };
    try {
      onSaved(client ? await clientsApi.update(client.client_id, input) : await clientsApi.create(input));
    } catch (e) {
      setError((e as Error).message);
      setSaving(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <div className="dlg-body">
        <h2>{client ? `Edit ${client.client_name}` : "New OAuth client"}</h2>
        {client ? (
          <div className="hint">
            client_id <span className="mono">{client.client_id}</span>
          </div>
        ) : (
          <label>
            Client ID
            <input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="random if empty" pattern="[A-Za-z0-9._~\-]{3,64}" />
          </label>
        )}
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} />
          <span className="hint">Shown in emails sent for this app.</span>
        </label>
        <label>
          Client type
          <select value={authMethod} onChange={(e) => setAuthMethod(e.target.value as OAuthClient["token_endpoint_auth_method"])}>
            {Object.entries(AUTH_METHOD_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <span className="hint">Browser and mobile apps are public; server-side apps that can keep a secret are confidential.</span>
        </label>
        <div>
          <div className="field-label">Grant types</div>
          <div className="check-row">
            <label className="check">
              <input type="checkbox" checked={grants.has("authorization_code")} onChange={() => toggleGrant("authorization_code")} />{" "}
              authorization_code (users sign in)
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={grants.has("refresh_token")}
                disabled={!userSignIn}
                onChange={() => toggleGrant("refresh_token")}
              />{" "}
              refresh_token
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={grants.has("client_credentials")}
                disabled={authMethod === "none"}
                onChange={() => toggleGrant("client_credentials")}
              />{" "}
              client_credentials (machine-to-machine)
            </label>
          </div>
          <span className="hint">
            client_credentials needs a confidential client; its tokens get only API scopes (e.g. secrets) and no refresh / ID token.
          </span>
        </div>
        {userSignIn && (
          <label>
            Redirect URIs
            <textarea value={redirects} onChange={(e) => setRedirects(e.target.value)} rows={3} required placeholder="https://app.example.com/callback" />
            <span className="hint">One per line, matched exactly. https (http only for localhost).</span>
          </label>
        )}
        <div>
          <div className="field-label">Scopes</div>
          <div className="check-row">
            {SCOPES.map((s) => (
              <label className="check" key={s}>
                <input type="checkbox" checked={scopes.has(s)} onChange={() => toggleScope(s)} /> {s}
              </label>
            ))}
          </div>
        </div>
        <label>
          Email verification
          <select value={emailMethod} onChange={(e) => setEmailMethod(e.target.value as "code" | "link")}>
            <option value="code">6-digit code (OTP)</option>
            <option value="link">Link</option>
          </select>
        </label>
        <label>
          Sender email (From)
          <input value={mailFrom} onChange={(e) => setMailFrom(e.target.value)} placeholder={defaultMailFrom} maxLength={200} />
          <span className="hint">
            "Name &lt;address@domain&gt;" or an address. Empty = server default ({defaultMailFrom}). Your SMTP server must be
            allowed to send from this address.
          </span>
        </label>
        <label>
          Initiate login URI
          <input value={initiate} onChange={(e) => setInitiate(e.target.value)} placeholder="https://app.example.com/login" />
          <span className="hint">
            OpenID Connect initiate_login_uri: where an emailed sign-in link sends the browser so the app starts a new sign-in.
            Without it, the link finishes the original sign-in.
          </span>
        </label>
        <label>
          Home page
          <input value={homepage} onChange={(e) => setHomepage(e.target.value)} placeholder="https://app.example.com" />
        </label>
        <div className="name-row">
          <label>
            Access token (s)
            <input type="number" min={60} max={86400} value={accessTtl} onChange={(e) => setAccessTtl(e.target.value)} required />
          </label>
          <label>
            Refresh token (s)
            <input type="number" min={300} max={31536000} value={refreshTtl} onChange={(e) => setRefreshTtl(e.target.value)} required />
          </label>
          <label>
            ID token (s)
            <input type="number" min={60} max={86400} value={idTtl} onChange={(e) => setIdTtl(e.target.value)} required />
          </label>
        </div>
        <div className="error-text">{error}</div>
      </div>
      <div className="dlg-foot">
        <button type="button" className="btn-ghost" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className="btn-primary" disabled={saving}>
          {saving ? "Saving…" : client ? "Save" : "Create"}
        </button>
      </div>
    </form>
  );
}

/* ---------- owners of client management (client_admin) + master credential ---------- */

function OwnersPanel({
  clientsApi,
  onClose,
  onMasterDisabled
}: {
  clientsApi: ClientsApi;
  onClose?: () => void;
  onMasterDisabled?: () => void;
}) {
  const [view, setView] = useState<OwnersView | null>(null);
  const [you, setYou] = useState<OwnersView["you"]>();
  const [username, setUsername] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    clientsApi
      .owners()
      .then((v) => {
        setView(v);
        setYou(v.you);
      })
      .catch((e: Error) => setError(e.message));
  }, [clientsApi]);

  const act = async (fn: () => Promise<OwnersView>) => {
    setBusy(true);
    setError("");
    try {
      setView(await fn());
      return true;
    } catch (e) {
      setError((e as Error).message);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const add = async (event: FormEvent) => {
    event.preventDefault();
    if (await act(() => clientsApi.addOwner(username.trim()))) setUsername("");
  };

  const disableMaster = async () => {
    const self = you?.kind === "master";
    const ok = confirm(
      "Disable the master credential? MASTER_CREDENTIALS will stop working even if it stays in the server's env." +
        (self ? " You are signed in with it, so you will be signed out." : "")
    );
    if (ok && (await act(() => clientsApi.disableMaster())) && self) onMasterDisabled?.();
  };

  if (!view) {
    return (
      <div className="dlg-body">
        {error ? <div className="error-text">{error}</div> : <div className="skeleton" />}
      </div>
    );
  }

  const { master, owners } = view;
  const lastOwnerLocked = owners.length <= 1 && !master.enabled;

  return (
    <div>
      <div className="dlg-body">
        <h2>Owners</h2>
        <p className="hint">
          Users who may manage OAuth clients and their owners (role client_admin) — separate from the admin role, which manages
          users and secrets.
        </p>

        <div className="device-row">
          <div className="device-main">
            <div>
              <strong>Master credential</strong>
              {master.username && (
                <span className="hint">
                  {" "}
                  {master.username} · {master.email}
                </span>
              )}
              {!master.configured ? (
                <span className="badge">Not configured</span>
              ) : master.enabled ? (
                <span className="badge badge-warn">Active</span>
              ) : (
                <span className="badge badge-ok">Disabled</span>
              )}
              {you?.kind === "master" && <span className="badge">You</span>}
            </div>
            <div className="hint">
              {master.enabled
                ? owners.length === 0
                  ? "MASTER_CREDENTIALS from the server env. Add an owner, then disable it so a leaked value is useless."
                  : "MASTER_CREDENTIALS from the server env. Disable it now that an owner can take over."
                : master.disabledAt
                  ? `Disabled ${timeAgo(master.disabledAt)} by ${master.disabledBy}. Recovery on the server: pnpm master:enable`
                  : "MASTER_CREDENTIALS is not set on the server."}
            </div>
          </div>
          <div className="device-actions">
            {master.enabled && (
              <button
                className="btn-danger"
                disabled={busy || owners.length === 0}
                title={owners.length === 0 ? "Add an owner first" : "Disable the master credential"}
                onClick={disableMaster}
              >
                Disable
              </button>
            )}
            {master.configured && !master.enabled && you?.kind === "user" && (
              <button className="btn-ghost" disabled={busy} onClick={() => act(() => clientsApi.enableMaster())}>
                Re-enable
              </button>
            )}
          </div>
        </div>

        <div className="grant-list">
          {owners.length === 0 && <p className="hint">No owners yet.</p>}
          {owners.map((o) => (
            <div className="grant-row" key={o.id}>
              <span className="mono">@{o.username}</span>
              <span className="hint">{o.email ?? ""}</span>
              {you?.kind === "user" && you.id === o.id && <span className="badge">You</span>}
              <button
                className="btn-ghost push-right"
                disabled={busy || lastOwnerLocked}
                title={lastOwnerLocked ? "The last owner cannot be removed while the master is disabled" : "Remove owner"}
                onClick={() => confirm(`Remove @${o.username} as an owner?`) && act(() => clientsApi.removeOwner(o.username))}
              >
                <TrashIcon />
              </button>
            </div>
          ))}
          <form className="grant-row add" onSubmit={add}>
            <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" required />
            <button type="submit" className="btn-primary" disabled={busy || !username.trim()}>
              Add owner
            </button>
          </form>
        </div>
        <div className="error-text">{error}</div>
      </div>
      {onClose && (
        <div className="dlg-foot">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Done
          </button>
        </div>
      )}
    </div>
  );
}
