import { useState, type FormEvent } from "react";
import type { Account } from "../api";
import { fillBrowser, releaseBrowser } from "../fill-window";

type KeyGateProps = {
  mode: "setup" | "unlock";
  account: Account;
  onSubmit: (password: string) => Promise<void>;
  onReset: (password: string) => Promise<void>;
  onLogout: () => void;
};

export function KeyGate({ mode, account, onSubmit, onReset, onLogout }: KeyGateProps) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [resetting, setResetting] = useState(false);
  const [understand, setUnderstand] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const google = account.provider === "google";
  const secretLabel = google ? "Encryption passphrase" : "Password";

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (password.length < 8) {
      setError("Use at least 8 characters.");
      return;
    }
    if ((mode === "setup" || resetting) && password !== confirm) {
      setError("Those entries don't match.");
      return;
    }
    if (resetting && !understand) {
      setError("Confirm that older messages will stay unreadable.");
      return;
    }
    setBusy(true);
    setError(null);
    fillBrowser();
    try {
      if (resetting) await onReset(password);
      else await onSubmit(password);
    } catch (caught) {
      releaseBrowser();
      setError(caught instanceof Error ? caught.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-page single">
      <section className="auth-card">
        <p className="eyebrow">@{account.username}</p>
        <h1>{mode === "setup" ? "Protect your keys" : resetting ? "Reset encryption keys" : "Unlock your keys"}</h1>
        <p className="hint">
          {mode === "setup"
            ? "Gmail only signs you in. This passphrase encrypts your keys and is never sent to the server. You'll need it on every new browser."
            : resetting
              ? "A new key pair replaces the old one. Messages already exchanged stay on the server, and this browser will not be able to read them."
              : google
                ? "Enter the encryption passphrase you created for Whisper. It never leaves this browser."
                : "Enter your password to decrypt your keys on this browser."}
        </p>
        <form onSubmit={(event) => void submit(event)}>
          <label className="field">
            {resetting && google ? "New passphrase" : secretLabel}
            <input
              type="password"
              autoComplete={mode === "unlock" && !resetting ? "current-password" : "new-password"}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              minLength={8}
            />
          </label>
          {(mode === "setup" || resetting) && (
            <label className="field">
              Confirm
              <input type="password" autoComplete="new-password" value={confirm} onChange={(event) => setConfirm(event.target.value)} required minLength={8} />
            </label>
          )}
          {resetting && (
            <label className="check">
              <input type="checkbox" checked={understand} onChange={(event) => setUnderstand(event.target.checked)} />
              I understand older messages will be unreadable.
            </label>
          )}
          {error && <p className="error">{error}</p>}
          <button className="primary" type="submit" disabled={busy}>
            {busy ? "Encrypting…" : resetting ? "Replace keys" : mode === "setup" ? "Save passphrase" : "Unlock"}
          </button>
        </form>
        <div className="row-actions">
          {mode === "unlock" && (
            <button type="button" className="text" onClick={() => { setResetting((value) => !value); setError(null); }}>
              {resetting ? "Back to unlock" : "Forgot this secret?"}
            </button>
          )}
          <button type="button" className="text" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </section>
    </main>
  );
}
