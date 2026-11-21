import type { CipherBundle, GroupEnvelope, MessageEnvelope, WrappedIdentity } from "@whisper/shared";

export type PublicUser = {
  id: string;
  username: string;
  displayName: string;
  keysReady: boolean;
  ecdhPublic: string | null;
  ecdsaPublic: string | null;
};

export type Account = PublicUser & {
  provider: "password" | "google";
  wrappedEcdh: string | null;
  wrappedEcdsa: string | null;
  wrapSalt: string | null;
  wrapIterations: number | null;
};

export type ServerMessage = {
  id: string;
  conversationId: string;
  senderId: string;
  nonce: string;
  createdAt: string;
  forRecipient: CipherBundle;
  forSender: CipherBundle;
  forMe: CipherBundle | null;
  signature: string;
  collectsReplies: boolean;
  editedAt: string | null;
  reactions: MessageReaction[];
};

export type MessageReaction = {
  userId: string;
  emoji: string;
};

export type MessagePin = {
  messageId: string;
  pinnedBy: string;
  pinnedAt: string;
  message: ServerMessage;
};

export type MemberUser = PublicUser & { role: "admin" | "member" };

export type Conversation = {
  id: string;
  kind: "direct" | "group";
  title: string | null;
  createdAt: string;
  lastMessageAt: string | null;
  unreadCount: number;
  peerLastReadAt: string | null;
  hidden: boolean;
  peerOnline?: boolean;
  viewerRole: "admin" | "member" | null;
  peer: PublicUser | null;
  members: MemberUser[];
  lastMessage: ServerMessage | null;
};

export const TOKEN_KEY = "whisper.token";

let authToken: string | null = null;
const exchangeRequests = new Map<string, Promise<{ token: string; user: Account }>>();

export function setAuthToken(token: string | null) {
  authToken = token;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (authToken) headers.set("Authorization", `Bearer ${authToken}`);
  let response: Response;
  try {
    response = await fetch(path, { ...init, headers });
  } catch {
    throw new Error("Can't reach the Whisper server.");
  }
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) throw new Error(data.error || "Request failed.");
  return data;
}

export function getConfig() {
  return request<{ googleEnabled: boolean }>("/api/config");
}

export function registerAccount(body: WrappedIdentity & { username: string; displayName: string; authVerifier: string }) {
  return request<{ token: string; user: Account }>("/api/auth/register", { method: "POST", body: JSON.stringify(body) });
}

export function loginAccount(username: string, authVerifier: string) {
  return request<{ token: string; user: Account }>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, authVerifier }),
  });
}

export function exchangeCode(code: string) {
  const existing = exchangeRequests.get(code);
  if (existing) return existing;
  const promise = request<{ token: string; user: Account }>("/api/auth/exchange", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
  exchangeRequests.set(code, promise);
  return promise;
}

export function logoutAccount() {
  return request<{ ok: boolean }>("/api/auth/logout", { method: "POST" });
}

export function currentAccount() {
  return request<{ user: Account }>("/api/auth/me");
}

export function confirmPassword(authVerifier: string) {
  return request<{ ok: boolean }>("/api/auth/confirm", {
    method: "POST",
    body: JSON.stringify({ authVerifier }),
  });
}

export function changePassword(body: WrappedIdentity & { authVerifier: string; nextAuthVerifier: string }) {
  return request<{ user: Account }>("/api/auth/password", { method: "POST", body: JSON.stringify(body) });
}

export function saveKeys(keys: WrappedIdentity) {
  return request<{ user: Account }>("/api/keys", { method: "POST", body: JSON.stringify(keys) });
}

export function resetKeys(keys: WrappedIdentity) {
  return request<{ user: Account }>("/api/keys/reset", { method: "POST", body: JSON.stringify(keys) });
}

export function searchUsers(query: string) {
  return request<{ users: PublicUser[] }>(`/api/users/search?q=${encodeURIComponent(query)}`);
}

export function listUsers() {
  return request<{ users: PublicUser[] }>("/api/users");
}

export function listConversations() {
  return request<{ conversations: Conversation[] }>("/api/conversations");
}

export function setChatHidden(conversationId: string, hidden: boolean) {
  return request<{ conversation: Conversation }>(`/api/conversations/${conversationId}/hidden`, {
    method: "POST",
    body: JSON.stringify({ hidden }),
  });
}

export function removeChat(conversationId: string) {
  return request<{ ok: boolean }>(`/api/conversations/${conversationId}`, { method: "DELETE" });
}

export function openConversation(username: string) {
  return request<{ conversation: Conversation }>("/api/conversations", {
    method: "POST",
    body: JSON.stringify({ username }),
  });
}

export function listMessages(conversationId: string, before?: string) {
  const query = before ? `?before=${encodeURIComponent(before)}` : "";
  return request<{ messages: ServerMessage[]; hasMore: boolean; pins: MessagePin[] }>(`/api/conversations/${conversationId}/messages${query}`);
}

export function sendMessage(conversationId: string, envelope: MessageEnvelope | GroupEnvelope) {
  return request<{ message: ServerMessage }>(`/api/conversations/${conversationId}/messages`, {
    method: "POST",
    body: JSON.stringify(envelope),
  });
}

export function editMessage(conversationId: string, messageId: string, envelope: MessageEnvelope | GroupEnvelope) {
  return request<{ message: ServerMessage }>(`/api/conversations/${conversationId}/messages/${messageId}`, {
    method: "PUT",
    body: JSON.stringify(envelope),
  });
}

export function deleteMessage(conversationId: string, messageId: string, attachmentId?: string) {
  return request<{ ok: boolean; lastMessageAt: string | null }>(
    `/api/conversations/${conversationId}/messages/${messageId}`,
    { method: "DELETE", body: JSON.stringify({ attachmentId: attachmentId ?? null }) },
  );
}

export function setMessagePin(conversationId: string, messageId: string, pinned: boolean) {
  return request<{ pins: MessagePin[] }>(`/api/conversations/${conversationId}/messages/${messageId}/pin`, {
    method: "POST",
    body: JSON.stringify({ pinned }),
  });
}

export function setReaction(conversationId: string, messageId: string, emoji: string | null) {
  return request<{ reactions: MessageReaction[] }>(`/api/conversations/${conversationId}/messages/${messageId}/react`, {
    method: "POST",
    body: JSON.stringify({ emoji }),
  });
}

export function setCollectsReplies(conversationId: string, messageId: string, collects: boolean) {
  return request<{ message: ServerMessage }>(`/api/conversations/${conversationId}/messages/${messageId}/collect`, {
    method: "POST",
    body: JSON.stringify({ collects }),
  });
}

export function leaveGroup(conversationId: string) {
  return request<{ ok: boolean }>(`/api/groups/${conversationId}/members`, { method: "DELETE" });
}

export function removeGroupMember(conversationId: string, userId: string) {
  return request<{ conversation: Conversation }>(`/api/groups/${conversationId}/members/${userId}`, { method: "DELETE" });
}

export function addGroupMember(conversationId: string, username: string) {
  return request<{ conversation: Conversation }>(`/api/groups/${conversationId}/members`, {
    method: "POST",
    body: JSON.stringify({ username }),
  });
}

export function createGroup(title: string, usernames: string[]) {
  return request<{ conversation: Conversation }>("/api/groups", {
    method: "POST",
    body: JSON.stringify({ title, usernames }),
  });
}

export function markRead(conversationId: string, messageId: string) {
  return request<{ lastReadAt: string }>(`/api/conversations/${conversationId}/read`, {
    method: "POST",
    body: JSON.stringify({ messageId }),
  });
}

export async function uploadAttachment(conversationId: string, bytes: Uint8Array): Promise<{ id: string }> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const headers = new Headers({ "Content-Type": "application/octet-stream" });
  if (authToken) headers.set("Authorization", `Bearer ${authToken}`);
  let response: Response;
  try {
    response = await fetch(`/api/conversations/${conversationId}/attachments`, {
      method: "POST",
      headers,
      body: new Blob([copy.buffer]),
    });
  } catch {
    throw new Error("Can't reach the Whisper server.");
  }
  const data = (await response.json().catch(() => ({}))) as { id?: string; error?: string };
  if (!response.ok || !data.id) throw new Error(data.error || "The file wasn't uploaded.");
  return { id: data.id };
}

export async function downloadAttachment(conversationId: string, attachmentId: string): Promise<Uint8Array> {
  const headers = new Headers();
  if (authToken) headers.set("Authorization", `Bearer ${authToken}`);
  let response: Response;
  try {
    response = await fetch(`/api/conversations/${conversationId}/attachments/${attachmentId}`, { headers });
  } catch {
    throw new Error("Can't reach the Whisper server.");
  }
  if (!response.ok) {
    const data = (await response.json().catch(() => ({}))) as { error?: string };
    throw new Error(data.error || "Couldn't download the file.");
  }
  return new Uint8Array(await response.arrayBuffer());
}
