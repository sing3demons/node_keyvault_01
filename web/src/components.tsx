import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, type GeneratedKeyPair, type KeyPairOptions, type SecretSummary } from "./api";
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

/* ---------- <input type="date"> <-> ISO helpers (local time) ---------- */

const pad = (n: number) => String(n).padStart(2, "0");

/** ISO timestamp -> "YYYY-MM-DD" in the viewer's local time zone */
function toDateInput(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** "YYYY-MM-DD" -> ISO timestamp at the end of that local day; "" -> null */
function fromDateInput(date: string): string | null {
  return date ? new Date(`${date}T23:59:59`).toISOString() : null;
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

  const expired = !!secret.expiresOn && new Date(secret.expiresOn).getTime() < Date.now();

  return (
    <div className="row">
      <div className="row-main">
        <div className="name mono" title={secret.name}>
          {secret.name}
          {!secret.enabled && <span className="badge">disabled</span>}
          {expired && <span className="badge danger">expired</span>}
        </div>
        <div className="meta">
          <span title={secret.updatedOn && new Date(secret.updatedOn).toLocaleString()}>
            Updated {timeAgo(secret.updatedOn)}
          </span>
          {secret.expiresOn && (
            <span title={new Date(secret.expiresOn).toLocaleString()}>
              {" · "}
              {expired ? "Expired" : "Expires"} {timeAgo(secret.expiresOn)}
            </span>
          )}
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
  /** current expiry of the secret being edited (ISO), used to prefill the date picker */
  initialExpiresOn?: string;
  existingNames: string[];
  onClose: () => void;
  onSaved: (name: string, created: boolean) => void;
}

export function EditDialog({ open, editing, initialExpiresOn, existingNames, onClose, onSaved }: EditProps) {
  return (
    <Modal open={open} onClose={onClose}>
      <EditForm
        editing={editing}
        initialExpiresOn={initialExpiresOn}
        existingNames={existingNames}
        onClose={onClose}
        onSaved={onSaved}
      />
    </Modal>
  );
}

function EditForm({ editing, initialExpiresOn, existingNames, onClose, onSaved }: Omit<EditProps, "open">) {
  const [name, setName] = useState(editing ?? "");
  const [value, setValue] = useState("");
  const initialDate = toDateInput(initialExpiresOn);
  const [expiresDate, setExpiresDate] = useState(initialDate);
  const today = toDateInput(new Date().toISOString());
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
      // Key Vault creates a new version on every save, so always send the expiry (null clears it)
      await api.set(trimmed, value, fromDateInput(expiresDate));
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
        <label>
          Expires on
          <div className="date-field">
            <input
              type="date"
              value={expiresDate}
              onChange={(e) => setExpiresDate(e.target.value)}
              // block past dates, but let an already-expired secret keep its date while editing the value
              min={expiresDate === initialDate && initialDate < today ? undefined : today}
            />
            {expiresDate && (
              <button type="button" className="btn-ghost" onClick={() => setExpiresDate("")}>
                Clear
              </button>
            )}
          </div>
          <span className="hint">Optional. Leave empty for no expiry — expires at the end of the chosen day.</span>
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

/* ---------- generate RSA key pair ---------- */

interface KeyPairProps {
  open: boolean;
  existingNames: string[];
  onClose: () => void;
  onGenerated: (result: GeneratedKeyPair) => void;
  onCopied: () => void;
}

export function KeyPairDialog({ open, ...rest }: KeyPairProps) {
  return (
    <Modal open={open} onClose={rest.onClose}>
      <KeyPairForm {...rest} />
    </Modal>
  );
}

function KeyPairForm({ existingNames, onClose, onGenerated, onCopied }: Omit<KeyPairProps, "open">) {
  const [name, setName] = useState("");
  const [modulusLength, setModulusLength] = useState<KeyPairOptions["modulusLength"]>(2048);
  const [validDays, setValidDays] = useState(365);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<GeneratedKeyPair | null>(null);

  const trimmed = name.trim();
  const rotating = !!trimmed && existingNames.some((n) => n.toLowerCase() === `${trimmed}-private`.toLowerCase());

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const generated = await api.generateKeyPair(trimmed, { modulusLength, validDays });
      setResult(generated);
      onGenerated(generated);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    const jwks = JSON.stringify(result.jwks, null, 2);
    return (
      <div>
        <div className="dlg-body">
          <h2>Key pair generated</h2>
          <dl className="kv">
            <dt>kid</dt>
            <dd className="mono">{result.kid}</dd>
            <dt>Private key</dt>
            <dd className="mono">{result.privateSecretName}</dd>
            <dt>Public JWKS</dt>
            <dd className="mono">{result.publicSecretName}</dd>
            <dt>Expires</dt>
            <dd>{new Date(result.expiresOn).toLocaleString()}</dd>
          </dl>
          <label>
            Public JWKS
            <textarea className="mono jwks" value={jwks} readOnly />
            <span className="hint">The private key stays in Key Vault — reveal it from the secret list if you need it.</span>
          </label>
        </div>
        <div className="dlg-foot">
          <button
            type="button"
            className="btn-ghost"
            onClick={() => navigator.clipboard.writeText(jwks).then(onCopied)}
          >
            <CopyIcon /> Copy JWKS
          </button>
          <button type="button" className="btn-primary" onClick={onClose} autoFocus>
            Done
          </button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={submit}>
      <div className="dlg-body">
        <h2>Generate RSA key pair</h2>
        <label>
          Name
          <input
            className="mono"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            required
            maxLength={119}
            pattern="[0-9A-Za-z\-]+"
            placeholder="jwt-signing"
            autoComplete="off"
          />
          <span className="hint">
            Saved as <span className="mono">{trimmed || "name"}-private</span> and{" "}
            <span className="mono">{trimmed || "name"}-public</span>
          </span>
        </label>
        <div className="two-col">
          <label>
            Key size
            <select
              value={modulusLength}
              onChange={(e) => setModulusLength(Number(e.target.value) as KeyPairOptions["modulusLength"])}
            >
              <option value={2048}>2048 bits</option>
              <option value={3072}>3072 bits</option>
              <option value={4096}>4096 bits</option>
            </select>
          </label>
          <label>
            Valid for (days)
            <input
              type="number"
              min={1}
              max={3650}
              step={1}
              required
              value={validDays}
              onChange={(e) => setValidDays(e.target.valueAsNumber)}
            />
          </label>
        </div>
        {rotating && (
          <div className="warn-text">
            “{trimmed}” already exists — this creates a new key and the old public key disappears from the JWKS.
          </div>
        )}
        <div className="error-text">{error}</div>
      </div>
      <div className="dlg-foot">
        <button type="button" className="btn-ghost" onClick={onClose}>
          Cancel
        </button>
        <button type="submit" className="btn-primary" disabled={busy}>
          {busy ? "Generating…" : rotating ? "Rotate key" : "Generate"}
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
