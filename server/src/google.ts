import { randomBytes } from "node:crypto";

type PendingState = { expires: number };
type ExchangeCode = { token: string; expires: number };

const states = new Map<string, PendingState>();
const exchangeCodes = new Map<string, ExchangeCode>();

function prune(map: Map<string, { expires: number }>) {
  const now = Date.now();
  for (const [key, value] of map) {
    if (value.expires < now) map.delete(key);
  }
}

export function googleEnabled() {
  return Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
}

export function clientOrigin() {
  return process.env.CLIENT_ORIGIN || "http://localhost:5173";
}

export function googleRedirectUri() {
  return process.env.GOOGLE_REDIRECT_URI || "http://localhost:3001/api/auth/google/callback";
}

export function beginGoogleLogin() {
  prune(states);
  const state = randomBytes(16).toString("base64url");
  states.set(state, { expires: Date.now() + 10 * 60 * 1000 });
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", process.env.GOOGLE_CLIENT_ID ?? "");
  url.searchParams.set("redirect_uri", googleRedirectUri());
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", state);
  url.searchParams.set("prompt", "select_account");
  return url.toString();
}

export function consumeGoogleState(state: string) {
  const pending = states.get(state);
  states.delete(state);
  return Boolean(pending && pending.expires >= Date.now());
}

export async function exchangeGoogleCode(code: string) {
  const body = new URLSearchParams({
    code,
    client_id: process.env.GOOGLE_CLIENT_ID ?? "",
    client_secret: process.env.GOOGLE_CLIENT_SECRET ?? "",
    redirect_uri: googleRedirectUri(),
    grant_type: "authorization_code",
  });
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!tokenResponse.ok) throw new Error("Google token exchange failed.");
  const tokenJson = (await tokenResponse.json()) as { access_token?: string };
  if (!tokenJson.access_token) throw new Error("Google did not return an access token.");
  const profileResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${tokenJson.access_token}` },
  });
  if (!profileResponse.ok) throw new Error("Google profile request failed.");
  const profile = (await profileResponse.json()) as {
    sub?: string;
    email?: string;
    email_verified?: boolean;
    name?: string;
  };
  if (!profile.sub || !profile.email || profile.email_verified === false) {
    throw new Error("Google account is missing a verified email.");
  }
  return { sub: profile.sub, email: profile.email, name: profile.name?.trim() || "" };
}

export function createExchangeCode(token: string) {
  prune(exchangeCodes);
  const code = randomBytes(24).toString("base64url");
  exchangeCodes.set(code, { token, expires: Date.now() + 60_000 });
  return code;
}

export function consumeExchangeCode(code: string) {
  const pending = exchangeCodes.get(code);
  exchangeCodes.delete(code);
  if (!pending || pending.expires < Date.now()) return null;
  return pending.token;
}
