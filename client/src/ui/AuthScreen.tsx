import { useState, type FormEvent } from "react";

const USERNAME = /^[a-z0-9_]{3,20}$/;

type AuthScreenProps = {
  googleEnabled: boolean;
  notice: string | null;
  onLogin: (username: string, password: string) => Promise<void>;
  onRegister: (username: string, displayName: string, password: string) => Promise<void>;
};

export function AuthScreen({ googleEnabled, notice, onLogin, onRegister }: AuthScreenProps) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const normalized = username.trim().toLowerCase();
    if (!USERNAME.test(normalized)) {
      setError("Usernames are 3–20 characters: letters, numbers, and underscores.");
      return;
    }
    if (password.length < 8) {
      setError("Use at least 8 characters.");
      return;
    }
    if (mode === "register" && password !== confirm) {
      setError("Those passwords don't match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (mode === "login") await onLogin(normalized, password);
      else await onRegister(normalized, displayName.trim() || normalized, password);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-hero">
        <div className="mark" aria-hidden="true">
          <LockIcon />
        </div>
        <p className="eyebrow">Private web chat</p>
        <h1>Whisper</h1>
        <p className="lede">
          Messages are encrypted in your browser before they reach the server. A password or Gmail account gets you in.
          The secret that wraps your keys stays on this device.
        </p>
        <ul>
          <li>One-to-one chats with live delivery</li>
          <li>Typing indicators and read receipts</li>
          <li>A safety number you can compare in person</li>
        </ul>
      </section>
      <section className="auth-card">
        <div className="segmented" role="tablist" aria-label="Account">
          <button type="button" role="tab" aria-selected={mode === "login"} className={mode === "login" ? "on" : ""} onClick={() => setMode("login")}>
            Log in
          </button>
          <button type="button" role="tab" aria-selected={mode === "register"} className={mode === "register" ? "on" : ""} onClick={() => setMode("register")}>
            Create account
          </button>
        </div>
        <form onSubmit={(event) => void submit(event)}>
          <label className="field">
            Username
            <input
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="alice"
              required
            />
          </label>
          {mode === "register" && (
            <label className="field">
              Display name
              <input
                autoComplete="nickname"
                value={displayName}
                onChange={(event) => setDisplayName(event.target.value)}
                placeholder="Alice"
                maxLength={40}
              />
            </label>
          )}
          <label className="field">
            Password
            <span className="password-row">
              <input
                type={showPassword ? "text" : "password"}
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
                minLength={8}
              />
              <button type="button" className="ghost" onClick={() => setShowPassword((value) => !value)}>
                {showPassword ? "Hide" : "Show"}
              </button>
            </span>
          </label>
          {mode === "register" && (
            <label className="field">
              Confirm password
              <input
                type={showPassword ? "text" : "password"}
                autoComplete="new-password"
                value={confirm}
                onChange={(event) => setConfirm(event.target.value)}
                required
                minLength={8}
              />
            </label>
          )}
          <p className="hint">
            {mode === "register"
              ? "This password encrypts your keys before anything is saved. Whisper stores a login verifier, not the password itself."
              : "The same password unlocks your encrypted keys on this browser."}
          </p>
          {notice && <p className="notice">{notice}</p>}
          {error && <p className="error">{error}</p>}
          <button className="primary" type="submit" disabled={busy}>
            {busy ? "Encrypting…" : mode === "login" ? "Log in" : "Create account"}
          </button>
        </form>
        <div className="divider">or</div>
        {googleEnabled ? (
          <a className="google" href="/api/auth/google">
            Continue with Gmail
          </a>
        ) : (
          <button
            type="button"
            className="google"
            onClick={() =>
              setError("Gmail sign-in needs a Google OAuth client in the server .env file. Username and password work in the meantime.")
            }
          >
            Continue with Gmail
          </button>
        )}
      </section>
    </main>
  );
}

function LockIcon() {
  return (
    <svg viewBox="0 0 24 24" className="icon">
      <rect x="5" y="11" width="14" height="10" rx="2" fill="none" stroke="currentColor" strokeWidth="1.8" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" fill="none" stroke="currentColor" strokeWidth="1.8" />
    </svg>
  );
}
