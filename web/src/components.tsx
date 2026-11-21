import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  LANGUAGES,
  PERMISSIONS,
  type Account,
  type AdminUser,
  type Device,
  type Grant,
  type Permission,
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
            We sent a link to <strong>{pending.email}</strong>. Open it — on this or any other device — to confirm your
            email address.
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
