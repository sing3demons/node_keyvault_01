import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, LANGUAGES, type Account, type SecretSummary } from "./api";
import { CopyIcon, EditIcon, EyeIcon, EyeOffIcon, TrashIcon } from "./icons";

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

/* ---------- secret row ---------- */

interface RowProps {
  secret: SecretSummary;
  onEdit: () => void;
  onDelete: () => void;
  onError: (message: string) => void;
  onCopied: () => void;
}

export function SecretRow({ secret, onEdit, onDelete, onError, onCopied }: RowProps) {
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
          Updated {timeAgo(secret.updatedOn)}
        </div>
      </div>

      <div className="value mono">
        {value === null ? <span className="masked">••••••••••••</span> : <span title={value}>{value}</span>}
        <button
          className="icon-btn"
          disabled={busy}
          title={value === null ? "Show value" : "Hide value"}
          onClick={() => (value === null ? withValue(setValue) : setValue(null))}
        >
          {value === null ? <EyeIcon /> : <EyeOffIcon />}
        </button>
      </div>

      <div className="actions">
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
        <button className="icon-btn" title="Edit" onClick={onEdit}>
          <EditIcon />
        </button>
        <button className="icon-btn danger" title="Delete" onClick={onDelete}>
          <TrashIcon />
        </button>
      </div>
    </div>
  );
}

/* ---------- create / edit dialog ---------- */

interface EditProps {
  open: boolean;
  /** name of the secret being edited; null = create */
  editing: string | null;
  existingNames: string[];
  onClose: () => void;
  onSaved: (name: string, created: boolean) => void;
}

export function EditDialog({ open, editing, existingNames, onClose, onSaved }: EditProps) {
  return (
    <Modal open={open} onClose={onClose}>
      <EditForm editing={editing} existingNames={existingNames} onClose={onClose} onSaved={onSaved} />
    </Modal>
  );
}

function EditForm({ editing, existingNames, onClose, onSaved }: Omit<EditProps, "open">) {
  const [name, setName] = useState(editing ?? "");
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(!!editing);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!editing) return;
    api
      .get(editing)
      .then(setValue)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [editing]);

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
            placeholder={loading ? "Loading…" : "secret value"}
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
}

export function AccountDialog({ account, open, onClose, onSaved }: AccountProps) {
  return (
    <Modal open={open && !!account} onClose={onClose}>
      {account && <AccountForm key={account.id} account={account} onClose={onClose} onSaved={onSaved} />}
    </Modal>
  );
}

type ProfileDraft = { lang: string; label: string; firstName: string; lastName: string };

function AccountForm({ account, onClose, onSaved }: { account: Account } & Pick<AccountProps, "onClose" | "onSaved">) {
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
          Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
        </label>
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
