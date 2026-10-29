import { useEffect, useState } from "react";
import {
  deriveAuthVerifier,
  generateIdentity,
  unwrapIdentity,
  wrapIdentity,
  type Identity,
  type WrappedIdentity,
} from "@whisper/shared";
import {
  TOKEN_KEY,
  confirmPassword,
  currentAccount,
  exchangeCode,
  getConfig,
  loginAccount,
  logoutAccount,
  registerAccount,
  resetKeys,
  saveKeys,
  setAuthToken,
  type Account,
} from "./api";
import { clearIdentity, loadIdentity, saveIdentity } from "./idb";
import { AuthScreen } from "./ui/AuthScreen";
import { ChatScreen } from "./ui/ChatScreen";
import { KeyGate } from "./ui/KeyGate";

type Phase = "boot" | "auth" | "setup" | "unlock" | "chat";

function wrappedFromAccount(account: Account): WrappedIdentity {
  if (
    !account.ecdhPublic ||
    !account.ecdsaPublic ||
    !account.wrappedEcdh ||
    !account.wrappedEcdsa ||
    !account.wrapSalt ||
    !account.wrapIterations
  ) {
    throw new Error("Encryption keys are missing.");
  }
  return {
    ecdhPublic: account.ecdhPublic,
    ecdsaPublic: account.ecdsaPublic,
    wrappedEcdh: account.wrappedEcdh,
    wrappedEcdsa: account.wrappedEcdsa,
    wrapSalt: account.wrapSalt,
    wrapIterations: account.wrapIterations,
  };
}

export function App() {
  const [phase, setPhase] = useState<Phase>("boot");
  const [user, setUser] = useState<Account | null>(null);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [googleEnabled, setGoogleEnabled] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  async function enterAccount(account: Account) {
    setUser(account);
    try {
      const stored = await loadIdentity(account.id);
      if (stored) {
        setIdentity(stored);
        setPhase("chat");
        return;
      }
    } catch {
      // IndexedDB can be blocked; the passphrase screen still unlocks this session.
    }
    setIdentity(null);
    setPhase(account.wrappedEcdh ? "unlock" : "setup");
  }

  useEffect(() => {
    let cancelled = false;
    async function boot() {
      try {
        const config = await getConfig();
        if (!cancelled) setGoogleEnabled(config.googleEnabled);
      } catch {
        if (!cancelled) setNotice("The Whisper server isn't running yet.");
      }

      const params = new URLSearchParams(location.search);
      const authError = params.get("auth_error");
      if (authError && !cancelled) {
        setNotice(
          authError === "google_disabled"
            ? "Gmail sign-in isn't configured on this server yet. Create a username and password instead."
            : "Gmail sign-in didn't finish. Try again, or use a username and password.",
        );
      }

      const code = params.get("code");
      if (code || authError) history.replaceState({}, "", "/");

      try {
        if (code) {
          const session = await exchangeCode(code);
          sessionStorage.setItem(TOKEN_KEY, session.token);
          setAuthToken(session.token);
          if (!cancelled) await enterAccount(session.user);
          return;
        }
        const existing = sessionStorage.getItem(TOKEN_KEY);
        if (!existing) {
          if (!cancelled) setPhase("auth");
          return;
        }
        setAuthToken(existing);
        const { user: account } = await currentAccount();
        if (!cancelled) await enterAccount(account);
      } catch (error) {
        sessionStorage.removeItem(TOKEN_KEY);
        setAuthToken(null);
        if (!cancelled) {
          setPhase("auth");
          if (code) setNotice(error instanceof Error ? error.message : "Sign-in failed.");
        }
      }
    }
    void boot();
    return () => {
      cancelled = true;
    };
  }, []);

  async function logout() {
    try {
      await logoutAccount();
    } catch {
      // Local sign-out still stands if the server is unreachable.
    }
    if (user) await clearIdentity(user.id).catch(() => undefined);
    sessionStorage.removeItem(TOKEN_KEY);
    setAuthToken(null);
    setUser(null);
    setIdentity(null);
    setPhase("auth");
  }

  if (!globalThis.crypto?.subtle) {
    return (
      <main className="boot">
        <p>
          This browser turns encryption off on a plain http address. Open the https:// address for this computer, then
          continue past the certificate warning.
        </p>
      </main>
    );
  }

  if (phase === "boot") {
    return (
      <main className="boot">
        <p>Opening Whisper…</p>
      </main>
    );
  }

  if (phase === "auth" || !user) {
    return (
      <AuthScreen
        googleEnabled={googleEnabled}
        notice={notice}
        onLogin={async (username, password) => {
          const authVerifier = await deriveAuthVerifier(username, password);
          const session = await loginAccount(username, authVerifier);
          sessionStorage.setItem(TOKEN_KEY, session.token);
          setAuthToken(session.token);
          try {
            const unlocked = await unwrapIdentity(wrappedFromAccount(session.user), password);
            await saveIdentity(session.user.id, unlocked);
            setUser(session.user);
            setIdentity(unlocked);
            setPhase("chat");
          } catch {
            await logoutAccount().catch(() => undefined);
            sessionStorage.removeItem(TOKEN_KEY);
            setAuthToken(null);
            throw new Error("That password didn't unlock the encryption keys for this account.");
          }
        }}
        onRegister={async (username, displayName, password) => {
          const created = await generateIdentity();
          const wrapped = await wrapIdentity(created, password);
          const authVerifier = await deriveAuthVerifier(username, password);
          const session = await registerAccount({ username, displayName, authVerifier, ...wrapped });
          sessionStorage.setItem(TOKEN_KEY, session.token);
          setAuthToken(session.token);
          await saveIdentity(session.user.id, created);
          setUser(session.user);
          setIdentity(created);
          setPhase("chat");
        }}
      />
    );
  }

  if (phase === "setup" || phase === "unlock" || !identity) {
    return (
      <KeyGate
        mode={phase === "setup" ? "setup" : "unlock"}
        account={user}
        onLogout={() => void logout()}
        onSubmit={async (password) => {
          if (phase === "setup" || !user.wrappedEcdh) {
            const created = await generateIdentity();
            const wrapped = await wrapIdentity(created, password);
            const saved = await saveKeys(wrapped);
            await saveIdentity(saved.user.id, created);
            setUser(saved.user);
            setIdentity(created);
            setPhase("chat");
            return;
          }
          try {
            const unlocked = await unwrapIdentity(wrappedFromAccount(user), password);
            await saveIdentity(user.id, unlocked);
            setIdentity(unlocked);
            setPhase("chat");
          } catch {
            throw new Error(
              user.provider === "google"
                ? "That passphrase didn't unlock your keys."
                : "That password didn't unlock your keys.",
            );
          }
        }}
        onReset={async (password) => {
          if (user.provider === "password") {
            await confirmPassword(await deriveAuthVerifier(user.username, password));
          }
          const created = await generateIdentity();
          const wrapped = await wrapIdentity(created, password);
          const saved = user.wrappedEcdh ? await resetKeys(wrapped) : await saveKeys(wrapped);
          await saveIdentity(saved.user.id, created);
          setUser(saved.user);
          setIdentity(created);
          setPhase("chat");
        }}
      />
    );
  }

  return (
    <ChatScreen
      user={user}
      identity={identity}
      onLogout={() => void logout()}
      onAccount={(account, nextIdentity) => {
        setUser(account);
        setIdentity(nextIdentity);
      }}
    />
  );
}
