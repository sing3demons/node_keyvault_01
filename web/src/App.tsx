import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { api, type Account, type SecretSummary } from "./api";
import { addPasskey, getIdentity, logout, onIdentityChange, passkeysSupported, refresh, startLogin } from "./auth";
import {
  AccountDialog,
  DeleteDialog,
  ClientsDialog,
  DevicesDialog,
  EditDialog,
  SecretRow,
  ShareDialog,
  Toasts,
  TransferDialog,
  UsersDialog,
  type Toast
} from "./components";
import { LockIcon, PlusIcon, RefreshIcon, SearchIcon, UsersIcon } from "./icons";

type Health = { state: "loading" } | { state: "ok"; provider?: string } | { state: "error" };

export function App() {
  const [secrets, setSecrets] = useState<SecretSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [health, setHealth] = useState<Health>({ state: "loading" });
  const [editor, setEditor] = useState<{ open: boolean; name: string | null }>({ open: false, name: null });
  const [deleting, setDeleting] = useState<string | null>(null);
  const [sharing, setSharing] = useState<string | null>(null);
  const [transferring, setTransferring] = useState<SecretSummary | null>(null);
  const [usersOpen, setUsersOpen] = useState(false);
  const [devicesOpen, setDevicesOpen] = useState(false);
  const [clientsOpen, setClientsOpen] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [account, setAccount] = useState<Account | null>(null);
  const [accountOpen, setAccountOpen] = useState(false);
  // from the ID Token: shown right away, before /auth/me answers
  const identity = useSyncExternalStore(onIdentityChange, getIdentity);
  const shownName = account?.displayProfile
    ? `${account.displayProfile.firstName} ${account.displayProfile.lastName}`
    : (identity?.name ?? `@${account?.username ?? identity?.preferredUsername ?? ""}`);
  const username = account?.username ?? identity?.preferredUsername;
  const searchRef = useRef<HTMLInputElement>(null);

  const toast = useCallback((message: string, error = false) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, message, error }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), error ? 5000 : 2500);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setSecrets(await api.list());
    } catch (e) {
      toast((e as Error).message, true);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    api
      .me()
      .then(setAccount)
      .catch(() => {});
    load();
    api
      .health()
      .then((h) => setHealth({ state: "ok", provider: h.provider }))
      .catch(() => setHealth({ state: "error" }));
  }, [load]);

  // press "/" to focus search
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (document.activeElement?.tagName ?? "").toLowerCase();
      if (e.key === "/" && tag !== "input" && tag !== "textarea") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? secrets.filter((s) => s.name.toLowerCase().includes(q)) : secrets;
  }, [secrets, query]);

  const openCreate = () => setEditor({ open: true, name: null });

  const onAddPasskey = async () => {
    try {
      await addPasskey(navigator.platform ? `Passkey · ${navigator.platform}` : undefined);
      toast("Passkey added — you can now sign in with it");
    } catch (e) {
      const err = e as Error;
      if (err.name !== "NotAllowedError") toast(err.message, true);
    }
  };

  const onLogout = async () => {
    await logout();
    startLogin();
  };

  return (
    <div className="wrap">
      <header>
        <div className="brand">
          <div className="logo">
            <LockIcon />
          </div>
          <div>
            <h1>Key Vault Secrets</h1>
            <div className="sub">Manage secrets stored in Azure Key Vault</div>
          </div>
        </div>
        <div className="status">
          <span className={`dot ${health.state === "ok" ? "ok" : health.state === "error" ? "err" : ""}`} />
          {health.state === "ok" ? (health.provider ? `Connected · ${health.provider}` : "Connected") : health.state === "error" ? "API unreachable" : "Connecting…"}
        </div>
        <div className="user-bar">
          {(account || identity) && (
            <button
              className="btn-ghost"
              onClick={() => setAccountOpen(true)}
              disabled={!account}
              title={username ? `@${username}` : undefined}
            >
              {shownName}
            </button>
          )}
          {account?.roles.includes("admin") && (
            <button className="btn-ghost" onClick={() => setUsersOpen(true)} title="Manage users and admins">
              <UsersIcon /> <span className="label-text">Users</span>
            </button>
          )}
          {account?.roles.includes("client_admin") && (
            <button className="btn-ghost" onClick={() => setClientsOpen(true)} title="OAuth clients (apps that sign users in here)">
              🧩 <span className="label-text">Clients</span>
            </button>
          )}
          <button className="btn-ghost" onClick={() => setDevicesOpen(true)} title="Devices that signed in to your account">
            💻 <span className="label-text">Devices</span>
          </button>
          {passkeysSupported() && (
            <button className="btn-ghost" onClick={onAddPasskey} title="Register a passkey for this account">
              🔑 <span className="label-text">Add passkey</span>
            </button>
          )}
          <button className="btn-ghost" onClick={onLogout}>
            Log out
          </button>
        </div>
      </header>

      <div className="toolbar">
        <div className="search">
          <SearchIcon />
          <input
            ref={searchRef}
            type="search"
            placeholder="Search secrets…  ( / )"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoComplete="off"
          />
        </div>
        <button className="btn-ghost" title="Refresh" onClick={load} disabled={loading}>
          <RefreshIcon />
        </button>
        <button className="btn-primary" onClick={openCreate}>
          <PlusIcon />
          <span className="label-text">New secret</span>
        </button>
      </div>

      <div className="count">
        {!loading && secrets.length > 0 &&
          (query.trim()
            ? `${filtered.length} of ${secrets.length} secrets`
            : `${secrets.length} secret${secrets.length === 1 ? "" : "s"}`)}
      </div>

      <div className="card">
        {loading && secrets.length === 0 ? (
          [0, 1, 2].map((i) => (
            <div className="row" key={i}>
              <div className="skeleton" style={{ width: "60%" }} />
              <div className="skeleton" />
              <div className="skeleton" style={{ width: 80 }} />
            </div>
          ))
        ) : secrets.length === 0 ? (
          <div className="empty">
            <div className="big">🗝️</div>
            <h3>No secrets yet</h3>
            <div>Create your first secret to get started.</div>
            <button className="btn-primary" style={{ marginTop: 16 }} onClick={openCreate}>
              <PlusIcon /> New secret
            </button>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty">
            <h3>No matches</h3>
            <div>Nothing matches “{query}”.</div>
          </div>
        ) : (
          filtered.map((s) => (
            <SecretRow
              key={s.name}
              secret={s}
              onEdit={() => setEditor({ open: true, name: s.name })}
              onDelete={() => setDeleting(s.name)}
              onShare={() => setSharing(s.name)}
              onTransfer={() => setTransferring(s)}
              onError={(m) => toast(m, true)}
              onCopied={() => toast(`Copied “${s.name}” to clipboard`)}
            />
          ))
        )}
      </div>

      <EditDialog
        open={editor.open}
        editing={editor.name}
        canRead={editor.name === null || !!secrets.find((s) => s.name === editor.name)?.access.read}
        existingNames={secrets.map((s) => s.name)}
        onClose={() => setEditor({ open: false, name: null })}
        onSaved={(name, created) => {
          setEditor({ open: false, name: null });
          toast(created ? `Created “${name}”` : `Updated “${name}”`);
          load();
        }}
      />

      <ShareDialog name={sharing} onClose={() => setSharing(null)} onError={(m) => toast(m, true)} />

      <TransferDialog
        secret={transferring}
        onClose={() => setTransferring(null)}
        onTransferred={(name, owner) => {
          setTransferring(null);
          toast(`“${name}” now belongs to @${owner}`);
          load();
        }}
      />

      <UsersDialog open={usersOpen} currentUserId={account?.id} onClose={() => setUsersOpen(false)} />

      <DevicesDialog open={devicesOpen} onClose={() => setDevicesOpen(false)} />

      <ClientsDialog open={clientsOpen} onClose={() => setClientsOpen(false)} />

      <DeleteDialog
        name={deleting}
        onClose={() => setDeleting(null)}
        onError={(m) => toast(m, true)}
        onDeleted={(name) => {
          setDeleting(null);
          setSecrets((list) => list.filter((s) => s.name !== name));
          toast(`Deleted “${name}”`);
        }}
      />

      <AccountDialog
        account={account}
        open={accountOpen}
        onClose={() => setAccountOpen(false)}
        onSaved={(updated) => {
          setAccount(updated);
          setAccountOpen(false);
          refresh(); // new ID Token carrying the updated name / language
          toast(updated.email && !updated.emailVerified ? "Account updated — please verify your email" : "Account updated");
        }}
        onVerified={(updated) => {
          setAccount(updated);
          refresh(); // ID Token's email_verified is now true
          toast("Email verified");
        }}
      />

      <Toasts items={toasts} />
    </div>
  );
}
