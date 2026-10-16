import { Fragment, useEffect, useLayoutEffect, useRef, useState, type ClipboardEvent, type FormEvent, type KeyboardEvent } from "react";
import {
  decryptFile,
  decryptGroupMessage,
  decryptMessage,
  deriveAuthVerifier,
  encryptFile,
  encryptGroupMessage,
  encryptMessage,
  generateIdentity,
  packPayload,
  safetyNumber,
  sha256Base64,
  unpackPayload,
  wrapIdentity,
  type AttachmentMeta,
  type Identity,
  type QuotedMessage,
} from "@whisper/shared";
import {
  confirmPassword,
  changePassword as changePasswordRequest,
  createGroup,
  addGroupMember,
  leaveGroup,
  removeGroupMember,
  downloadAttachment,
  listConversations,
  listMessages,
  markRead,
  openConversation,
  resetKeys as resetKeysRequest,
  searchUsers,
  sendMessage,
  editMessage,
  deleteMessage,
  setCollectsReplies,
  setReaction,
  uploadAttachment,
  type Account,
  type Conversation,
  type MessageReaction,
  type ServerMessage,
} from "../api";
import { saveIdentity } from "../idb";
import { PhotoEditor } from "./PhotoEditor";

type SearchHit = {
  conversationId: string;
  nonce: string;
  snippet: string;
};

type ChatMessage = ServerMessage & {
  text: string;
  file: AttachmentMeta | null;
  reply: QuotedMessage | null;
  forwarded: boolean;
  localUrl?: string;
  failed: boolean;
  pending?: boolean;
};

type WsEvent =
  | { type: "hello"; onlineUserIds: string[] }
  | { type: "presence"; userId: string; online: boolean }
  | { type: "typing"; conversationId: string; userId: string; active: boolean }
  | { type: "read"; conversationId: string; userId: string; lastReadAt: string }
  | { type: "message"; message: ServerMessage }
  | { type: "edit"; message: ServerMessage }
  | { type: "delete"; conversationId: string; messageId: string; nonce: string; senderId: string; lastMessageAt: string | null; unreadCount?: number }
  | { type: "collect"; conversationId: string; messageId: string; nonce: string; collects: boolean }
  | { type: "react"; conversationId: string; messageId: string; nonce: string; reactions: MessageReaction[] }
  | { type: "conversation"; conversation: Conversation }
  | { type: "removed"; conversationId: string }
  | { type: "keys"; userId: string; ecdhPublic: string; ecdsaPublic: string };

type ChatScreenProps = {
  user: Account;
  identity: Identity;
  onLogout: () => void;
  onAccount: (account: Account, identity: Identity) => void;
};

const REACTION_EMOJI = ["👍", "❤️", "😂", "😮", "😢", "🙏", "🔥", "🎉"];

function singleEmoji(value: string) {
  if (!value.trim() || typeof Intl.Segmenter !== "function") return "";
  const parts = [...new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(value)].map((part) => part.segment);
  return [...parts].reverse().find((part) => /\p{Extended_Pictographic}/u.test(part)) ?? "";
}

function reactionGroups(reactions: MessageReaction[]) {
  const groups: Array<{ emoji: string; userIds: string[] }> = [];
  for (const reaction of reactions) {
    const group = groups.find((item) => item.emoji === reaction.emoji);
    if (group) group.userIds.push(reaction.userId);
    else groups.push({ emoji: reaction.emoji, userIds: [reaction.userId] });
  }
  return groups;
}

function chatTitle(conversation: Conversation) {
  return conversation.kind === "group" ? conversation.title || "Group" : conversation.peer?.displayName || "Chat";
}

function searchSnippet(text: string, needle: string) {
  const clean = text.replace(/\s+/g, " ").trim();
  const at = clean.toLowerCase().indexOf(needle);
  if (at < 0) return clean.slice(0, 80);
  const start = Math.max(0, at - 24);
  const end = at + needle.length + 36;
  return `${start > 0 ? "…" : ""}${clean.slice(start, end)}${end < clean.length ? "…" : ""}`;
}

function queryWords(query: string) {
  return query.trim().toLowerCase().split(/\s+/).filter(Boolean);
}

function textMatches(haystack: string, query: string, phrase: boolean) {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const value = haystack.toLowerCase();
  if (phrase) return value.includes(needle);
  return queryWords(needle).every((word) => value.includes(word));
}

function chatFields(conversation: Conversation) {
  if (conversation.kind === "group") {
    return [chatTitle(conversation), ...conversation.members.flatMap((member) => [member.displayName, member.username])].join(" ");
  }
  return `${conversation.peer?.displayName ?? ""} ${conversation.peer?.username ?? ""}`;
}

function matchesChat(conversation: Conversation, query: string, phrase = false) {
  return textMatches(chatFields(conversation), query, phrase);
}

async function searchConversations(
  conversations: Conversation[],
  query: string,
  phrase: boolean,
  identity: Identity,
  userId: string,
  isCancelled: () => boolean,
) {
  const needle = query.trim().toLowerCase();
  const found: SearchHit[] = [];
  for (const conversation of conversations) {
    if (isCancelled() || found.length >= 40) break;
    let before: string | undefined;
    for (let pageNumber = 0; pageNumber < 15 && found.length < 40; pageNumber += 1) {
      const page = await listMessages(conversation.id, before);
      if (isCancelled()) return found;
      for (const message of page.messages) {
        const revealed = await revealMessage(message, conversation, identity, userId);
        const haystack = `${revealed.text}\n${previewText(revealed)}`;
        if (!textMatches(haystack, query, phrase)) continue;
        const focus = phrase
          ? needle
          : queryWords(query).find((word) => haystack.toLowerCase().includes(word)) ?? needle;
        found.push({
          conversationId: conversation.id,
          nonce: revealed.nonce,
          snippet: searchSnippet(previewText(revealed) || revealed.text, focus),
        });
        if (found.length >= 40) break;
      }
      const oldest = page.messages[0];
      if (!page.hasMore || !oldest) break;
      before = oldest.createdAt;
    }
  }
  return found;
}

function personName(conversation: Conversation, senderId: string, mine: string) {
  if (senderId === mine) return "You";
  if (conversation.peer?.id === senderId) return conversation.peer.displayName;
  return conversation.members.find((member) => member.id === senderId)?.displayName || "Someone";
}

function memberKey(conversation: Conversation, senderId: string, identity: Identity, myId: string) {
  if (senderId === myId) return identity.ecdsaPublic;
  if (conversation.peer?.id === senderId) return conversation.peer.ecdsaPublic;
  return conversation.members.find((member) => member.id === senderId)?.ecdsaPublic ?? null;
}

function initials(name: string) {
  const parts = name.trim().split(/\s+/).slice(0, 2);
  return parts.map((part) => part[0]?.toUpperCase() ?? "").join("") || "?";
}

function hue(value: string) {
  let hash = 0;
  for (const character of value) hash = (hash * 31 + character.charCodeAt(0)) % 360;
  return hash;
}

function sameDay(left: string, right: string) {
  const a = new Date(left);
  const b = new Date(right);
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

function formatListTime(iso: string) {
  const date = new Date(iso);
  const now = new Date();
  if (sameDay(iso, now.toISOString())) return formatTime(iso);
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (sameDay(iso, yesterday.toISOString())) return "Yesterday";
  return date.toLocaleDateString([], { month: "short", day: "numeric" });
}

function dayLabel(iso: string) {
  const now = new Date();
  if (sameDay(iso, now.toISOString())) return "Today";
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (sameDay(iso, yesterday.toISOString())) return "Yesterday";
  return new Date(iso).toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" });
}

function mergeMessage(list: ChatMessage[], incoming: ChatMessage) {
  const index = list.findIndex((item) => item.nonce === incoming.nonce || item.id === incoming.id);
  if (index === -1) return [...list, incoming].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  const next = list.slice();
  const previous = next[index];
  const keepPrevious = incoming.failed && Boolean(previous.text || previous.file);
  next[index] = {
    ...incoming,
    text: keepPrevious ? previous.text : incoming.text,
    file: keepPrevious ? previous.file : (incoming.file ?? previous.file),
    reply: keepPrevious ? previous.reply : incoming.reply,
    forwarded: keepPrevious ? previous.forwarded : incoming.forwarded,
    collectsReplies: keepPrevious ? previous.collectsReplies : incoming.collectsReplies,
    reactions: keepPrevious ? previous.reactions : incoming.reactions ?? previous.reactions ?? [],
    editedAt: keepPrevious ? previous.editedAt : incoming.editedAt,
    localUrl: incoming.localUrl ?? previous.localUrl,
    failed: incoming.failed && !previous.text && !previous.file,
    pending: false,
  };
  return next;
}

function previewText(message: { text: string; file: AttachmentMeta | null; failed?: boolean; forwarded?: boolean }) {
  if (message.failed) return "Unable to decrypt";
  const caption = message.text.replace(/\s+/g, " ").trim();
  const body = caption || (message.file ? fileLabel(message.file) : "");
  if (!body) return "";
  return message.forwarded ? `Forwarded: ${body}` : body;
}

function pastedImage(data: DataTransfer | null) {
  if (!data) return null;
  for (const item of data.items) {
    if (item.kind !== "file" || !item.type.startsWith("image/")) continue;
    const file = item.getAsFile();
    if (file) return file;
  }
  for (const file of data.files) {
    if (file.type.startsWith("image/")) return file;
  }
  return null;
}

function fileLabel(file: AttachmentMeta) {
  if (file.voice) return "Voice message";
  return isPreviewableImage(file.type) ? "Photo" : file.name;
}

function formatDuration(ms: number) {
  const total = Math.max(0, Math.round(ms / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${minutes}:${seconds.toString().padStart(2, "0")}`;
}

function formatBytes(size: number) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(size < 10 * 1024 ? 1 : 0)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function isPreviewableImage(type: string) {
  return type === "image/jpeg" || type === "image/png" || type === "image/gif" || type === "image/webp";
}

type ImageKind = "jpeg" | "png" | "gif" | "webp" | "heic";

function kindFromType(type: string): ImageKind | null {
  const value = type.toLowerCase();
  if (value === "image/jpg" || value === "image/jpeg" || value === "image/pjpeg") return "jpeg";
  if (value === "image/png" || value === "image/x-png") return "png";
  if (value === "image/gif") return "gif";
  if (value === "image/webp") return "webp";
  if (value === "image/heic" || value === "image/heif" || value === "image/heic-sequence" || value === "image/heif-sequence") return "heic";
  return null;
}

function kindFromName(name: string): ImageKind | null {
  const ext = name.split(/[/\\]/).pop()?.split(".").pop()?.toLowerCase();
  if (ext === "jpg" || ext === "jpeg" || ext === "jpe") return "jpeg";
  if (ext === "png") return "png";
  if (ext === "gif") return "gif";
  if (ext === "webp") return "webp";
  if (ext === "heic" || ext === "heif") return "heic";
  return null;
}

async function sniffImage(file: File): Promise<ImageKind | null> {
  const bytes = new Uint8Array(await file.slice(0, 16).arrayBuffer());
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "jpeg";
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "png";
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return "gif";
  if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 && bytes[8] === 0x57 && bytes[9] === 0x45) return "webp";
  const brand = String.fromCharCode(...bytes.slice(4, 12));
  if (brand.startsWith("ftyp") && /heic|heix|heif|mif1|hevc/.test(String.fromCharCode(...bytes.slice(8, 12)))) return "heic";
  return null;
}

function retagPhoto(file: File, kind: ImageKind) {
  const type = kind === "jpeg" ? "image/jpeg" : kind === "png" ? "image/png" : kind === "gif" ? "image/gif" : kind === "webp" ? "image/webp" : "image/heic";
  const ext = kind === "jpeg" ? "jpg" : kind;
  const base = file.name.split(/[/\\]/).pop()?.trim();
  const name = base && base !== "blob" ? base : `photo.${ext}`;
  if (file.type === type && file.name === name) return file;
  return new File([file], name, { type, lastModified: file.lastModified || Date.now() });
}

async function preparePhoto(file: File) {
  const named = kindFromType(file.type) ?? kindFromName(file.name) ?? await sniffImage(file);
  if (named) return retagPhoto(file, named);
  return null;
}

function safeFileName(name: string) {
  const base = name.split(/[/\\]/).pop() ?? "file";
  const cleaned = base.replace(/[\u0000-\u001f]/g, "").trim().slice(0, 120);
  return cleaned || "file";
}

async function photoPngBlob(message: { conversationId: string; localUrl?: string; file: AttachmentMeta | null }) {
  const file = message.file;
  if (!file) throw new Error("Couldn't copy this photo.");
  const source = message.localUrl
    ? await (await fetch(message.localUrl)).blob()
    : await decryptedBlob(message.conversationId, file);
  if (source.type === "image/png") return source;
  const bitmap = await createImageBitmap(source);
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const context = canvas.getContext("2d");
  if (!context) throw new Error("Couldn't copy this photo.");
  context.drawImage(bitmap, 0, 0);
  bitmap.close();
  const png = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png"));
  if (!png) throw new Error("Couldn't copy this photo.");
  return png;
}

async function decryptedBlob(conversationId: string, file: AttachmentMeta) {
  const bytes = await decryptAttachment(conversationId, file);
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return new Blob([copy], { type: file.type || "application/octet-stream" });
}

async function decryptAttachment(conversationId: string, file: AttachmentMeta) {
  const ciphertext = await downloadAttachment(conversationId, file.id);
  const digest = await sha256Base64(ciphertext);
  if (digest !== file.sha256) throw new Error("This file failed its integrity check.");
  return decryptFile(ciphertext, file.key, file.iv);
}

async function revealMessage(message: ServerMessage, conversation: Conversation, identity: Identity, myId: string): Promise<ChatMessage> {
  const senderPublic = memberKey(conversation, message.senderId, identity, myId);
  if (!senderPublic) return { ...message, text: "", file: null, reply: null, forwarded: false, failed: true };
  try {
    const plaintext = message.forMe
      ? await decryptGroupMessage({
          conversationId: message.conversationId,
          senderId: message.senderId,
          nonce: message.nonce,
          memberId: myId,
          bundle: message.forMe,
          signature: message.signature,
          senderEcdsaPublic: senderPublic,
          myEcdhPrivate: identity.ecdhPrivate,
        })
      : await decryptMessage({
          envelope: message,
          conversationId: message.conversationId,
          senderId: message.senderId,
          senderEcdsaPublic: senderPublic,
          myEcdhPrivate: identity.ecdhPrivate,
          copy: message.senderId === myId ? "sender" : "recipient",
        });
    const payload = unpackPayload(plaintext);
    return {
      ...message,
      text: payload.text,
      file: payload.file,
      reply: payload.reply,
      forwarded: payload.forwarded,
      failed: false,
    };
  } catch {
    return { ...message, text: "", file: null, reply: null, forwarded: false, failed: true };
  }
}

function quoteLabel(quote: QuotedMessage, myId: string) {
  return quote.senderId === myId ? "You" : quote.sender;
}

function shownQuote(quote: QuotedMessage, byNonce: Map<string, ChatMessage>) {
  const target = byNonce.get(quote.id);
  if (!target || target.failed) return quote.preview;
  return previewText(target) || quote.preview;
}

function focusQuoted(id: string) {
  const el = document.getElementById(`msg-${id}`);
  if (!el) return;
  el.scrollIntoView({ behavior: "smooth", block: "center" });
  el.classList.add("quote-hit");
  window.setTimeout(() => el.classList.remove("quote-hit"), 1400);
}

function collectorNonce(message: ChatMessage, byNonce: Map<string, ChatMessage>) {
  const seen = new Set<string>();
  let current = message;
  while (current.reply && !seen.has(current.nonce)) {
    seen.add(current.nonce);
    const parent = byNonce.get(current.reply.id);
    if (!parent) return null;
    if (parent.collectsReplies) return parent.nonce;
    current = parent;
  }
  return null;
}

function repliesFor(parentNonce: string, messages: ChatMessage[], byNonce: Map<string, ChatMessage>) {
  return messages.filter((message) => collectorNonce(message, byNonce) === parentNonce);
}

export function ChatScreen({ user, identity, onLogout, onAccount }: ChatScreenProps) {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Record<string, ChatMessage[]>>({});
  const [hasMore, setHasMore] = useState<Record<string, boolean>>({});
  const [previews, setPreviews] = useState<Record<string, string>>({});
  const [draft, setDraft] = useState("");
  const [pendingFile, setPendingFile] = useState<File | null>(null);
  const [photoFile, setPhotoFile] = useState<File | null>(null);
  const [pendingPreview, setPendingPreview] = useState<string | null>(null);
  const [pendingVoice, setPendingVoice] = useState<number | null>(null);
  const [recording, setRecording] = useState(false);
  const [recordMs, setRecordMs] = useState(0);
  const [replyTo, setReplyTo] = useState<QuotedMessage | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [forwardSources, setForwardSources] = useState<ChatMessage[]>([]);
  const [selectedNonces, setSelectedNonces] = useState<string[]>([]);
  const [sharing, setSharing] = useState(false);
  const [shareError, setShareError] = useState("");
  const [forwardLookup, setForwardLookup] = useState("");
  const [forwardError, setForwardError] = useState("");
  const [forwarding, setForwarding] = useState(false);
  const [forwardNote, setForwardNote] = useState("");
  const [userQuery, setUserQuery] = useState("");
  const [userPhrase, setUserPhrase] = useState(false);
  const [wordQuery, setWordQuery] = useState("");
  const [wordPhrase, setWordPhrase] = useState(false);
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [searching, setSearching] = useState(false);
  const [chatQuery, setChatQuery] = useState("");
  const [chatPhrase, setChatPhrase] = useState(false);
  const [chatHits, setChatHits] = useState<SearchHit[]>([]);
  const [chatSearching, setChatSearching] = useState(false);
  const [actionMenu, setActionMenu] = useState<string | null>(null);
  const [reactMenu, setReactMenu] = useState<string | null>(null);
  const [emojiPick, setEmojiPick] = useState("");
  const [emojiDraft, setEmojiDraft] = useState("");
  const [copiedNonce, setCopiedNonce] = useState<string | null>(null);
  const [dialog, setDialog] = useState<null | "new" | "safety" | "profile" | "reset" | "password" | "forward" | "delete" | "group" | "people">(null);
  const [deleteTarget, setDeleteTarget] = useState<ChatMessage | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [openFolders, setOpenFolders] = useState<Record<string, boolean>>({});
  const [online, setOnline] = useState<Set<string>>(new Set());
  const [typing, setTyping] = useState<Record<string, string[]>>({});
  const [sendError, setSendError] = useState("");
  const [listError, setListError] = useState("");
  const [mobileThread, setMobileThread] = useState(false);
  const [sending, setSending] = useState(false);
  const [loadingEarlier, setLoadingEarlier] = useState(false);
  const [safety, setSafety] = useState<string[]>([]);
  const [fingerprint, setFingerprint] = useState<string[]>([]);
  const [showFingerprint, setShowFingerprint] = useState(false);
  const [lookup, setLookup] = useState("");
  const [lookupError, setLookupError] = useState("");
  const [groupTitle, setGroupTitle] = useState("");
  const [groupUser, setGroupUser] = useState("");
  const [groupMembers, setGroupMembers] = useState<string[]>([]);
  const [groupError, setGroupError] = useState("");
  const [groupBusy, setGroupBusy] = useState(false);
  const [resetSecret, setResetSecret] = useState("");
  const [resetConfirm, setResetConfirm] = useState("");
  const [resetUnderstood, setResetUnderstood] = useState(false);
  const [resetError, setResetError] = useState("");
  const [resetBusy, setResetBusy] = useState(false);
  const [passwordCurrent, setPasswordCurrent] = useState("");
  const [passwordNext, setPasswordNext] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [passwordBusy, setPasswordBusy] = useState(false);

  const conversationsRef = useRef(conversations);
  const messagesRef = useRef(messages);
  const activeIdRef = useRef(activeId);
  const identityRef = useRef(identity);
  const socketRef = useRef<WebSocket | null>(null);
  const scrollerRef = useRef<HTMLDivElement>(null);
  const stickRef = useRef(true);
  const draftsRef = useRef<Record<string, string>>({});
  const repliesRef = useRef<Record<string, QuotedMessage | null>>({});
  const editingIdsRef = useRef<Record<string, string | null>>({});
  const editStashRef = useRef<Record<string, { messageId: string; draft: string; reply: QuotedMessage | null }>>({});
  const forwardNoteTimer = useRef(0);
  const loadedRef = useRef<Set<string>>(new Set());
  const typingTimers = useRef<Record<string, number>>({});
  const typingStop = useRef(0);
  const typingSent = useRef(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recordStreamRef = useRef<MediaStream | null>(null);
  const recordChunksRef = useRef<Blob[]>([]);
  const recordStartedRef = useRef(0);
  const recordTimerRef = useRef(0);
  const discardRecordingRef = useRef(false);
  const recordingRef = useRef(false);
  const recordStartingRef = useRef(false);

  conversationsRef.current = conversations;
  messagesRef.current = messages;
  activeIdRef.current = activeId;
  identityRef.current = identity;

  const active = conversations.find((conversation) => conversation.id === activeId) ?? null;
  const activeMessages = activeId ? messages[activeId] ?? [] : [];
  const editing = editingId ? activeMessages.find((item) => item.id === editingId) ?? null : null;
  const unreadTotal = conversations.reduce((sum, conversation) => sum + conversation.unreadCount, 0);

  useEffect(() => {
    document.title = unreadTotal > 0 ? `(${unreadTotal}) Whisper` : "Whisper";
  }, [unreadTotal]);

  useEffect(() => {
    return () => {
      discardRecordingRef.current = true;
      const recorder = mediaRecorderRef.current;
      if (recorder && recorder.state !== "inactive") recorder.stop();
      else releaseRecording();
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    loadedRef.current.clear();
    setMessages({});
    listConversations()
      .then(async ({ conversations: list }) => {
        if (cancelled) return;
        conversationsRef.current = list;
        setConversations(list);
        setOnline(new Set(list.flatMap((conversation) => (conversation.peer && conversation.peerOnline ? [conversation.peer.id] : []))));
        const nextPreviews: Record<string, string> = {};
        for (const conversation of list) {
          if (!conversation.lastMessage) continue;
          const revealed = await revealMessage(conversation.lastMessage, conversation, identity, user.id);
          nextPreviews[conversation.id] = previewText(revealed);
        }
        if (!cancelled) setPreviews(nextPreviews);
        const openId = activeIdRef.current;
        const still = openId ? list.find((conversation) => conversation.id === openId) : undefined;
        if (still && !cancelled) {
          const page = await listMessages(still.id);
          const revealed = await Promise.all(
            page.messages.map((message) => revealMessage(message, still, identity, user.id)),
          );
          if (cancelled) return;
          loadedRef.current.add(still.id);
          setHasMore((current) => ({ ...current, [still.id]: page.hasMore }));
          setMessages((current) => ({ ...current, [still.id]: revealed }));
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) setListError(error instanceof Error ? error.message : "Couldn't load chats.");
      });
    return () => {
      cancelled = true;
    };
  }, [identity, user.id]);

  useEffect(() => {
    const peerKey = active?.peer?.ecdsaPublic;
    if (dialog !== "safety" || !peerKey) return;
    let cancelled = false;
    void safetyNumber(identity.ecdsaPublic, peerKey).then((groups) => {
      if (!cancelled) setSafety(groups);
    });
    return () => {
      cancelled = true;
    };
  }, [dialog, active, identity.ecdsaPublic]);

  useEffect(() => {
    if (dialog !== "profile" && dialog !== "reset") return;
    let cancelled = false;
    void safetyNumber(identity.ecdsaPublic, identity.ecdsaPublic).then((groups) => {
      if (!cancelled) setFingerprint(groups);
    });
    return () => {
      cancelled = true;
    };
  }, [dialog, identity.ecdsaPublic]);

  useEffect(() => {
    if (selectedNonces.length === 0) return;
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        setSelectedNonces([]);
        setShareError("");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selectedNonces.length]);

  useEffect(() => {
    if (!dialog) return;
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") setDialog(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [dialog]);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let stopped = false;
    let attempt = 0;
    let timer = 0;

    const connect = () => {
      const protocol = location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(`${protocol}://${location.host}/ws`);
      socketRef.current = socket;
      socket.onopen = () => {
        attempt = 0;
        socket?.send(JSON.stringify({ type: "auth", token: sessionStorage.getItem("whisper.token") }));
      };
      socket.onmessage = (event) => {
        try {
          void handleEvent(JSON.parse(String(event.data)) as WsEvent);
        } catch {
          // Ignore malformed socket payloads.
        }
      };
      socket.onclose = () => {
        if (stopped) return;
        attempt += 1;
        timer = window.setTimeout(connect, Math.min(8000, 500 * attempt));
      };
    };

    connect();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      socket?.close();
    };
    // The handler reads the latest state through refs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user.id]);

  useLayoutEffect(() => {
    const el = scrollerRef.current;
    if (!el || !stickRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [activeMessages, activeId, typing]);

  function sendSocket(payload: unknown) {
    if (socketRef.current?.readyState === WebSocket.OPEN) socketRef.current.send(JSON.stringify(payload));
  }

  function replaceConversations(next: Conversation[]) {
    conversationsRef.current = next;
    setConversations(next);
  }

  function forgetMessage(event: { conversationId: string; messageId: string; nonce: string; lastMessageAt: string | null }) {
    const existing = messagesRef.current[event.conversationId] ?? [];
    for (const item of existing) {
      if ((item.id === event.messageId || item.nonce === event.nonce) && item.localUrl) URL.revokeObjectURL(item.localUrl);
    }
    const remaining = existing.filter((item) => item.id !== event.messageId && item.nonce !== event.nonce);
    setMessages((current) => ({
      ...current,
      [event.conversationId]: (current[event.conversationId] ?? []).filter(
        (item) => item.id !== event.messageId && item.nonce !== event.nonce,
      ),
    }));
    const stash = editStashRef.current[event.conversationId];
    if (stash?.messageId === event.messageId) {
      delete editStashRef.current[event.conversationId];
      editingIdsRef.current[event.conversationId] = null;
      if (activeIdRef.current === event.conversationId) {
        setEditingId(null);
        setDraft(stash.draft);
        draftsRef.current[event.conversationId] = stash.draft;
        setReplyTo(stash.reply);
        repliesRef.current[event.conversationId] = stash.reply;
      }
    }
    const last = remaining[remaining.length - 1];
    const conversation = conversationsRef.current.find((item) => item.id === event.conversationId);
    const removedLast = conversation?.lastMessage?.id === event.messageId || conversation?.lastMessage?.nonce === event.nonce;
    if (last) setPreviews((current) => ({ ...current, [event.conversationId]: previewText(last) }));
    else if (removedLast || existing.length > remaining.length) setPreviews((current) => ({ ...current, [event.conversationId]: "" }));
    const next = conversationsRef.current.map((item) => {
      if (item.id !== event.conversationId) return item;
      return {
        ...item,
        lastMessageAt: event.lastMessageAt,
        lastMessage: item.lastMessage?.id === event.messageId || item.lastMessage?.nonce === event.nonce ? null : item.lastMessage,
      };
    });
    next.sort((a, b) => (b.lastMessageAt ?? b.createdAt).localeCompare(a.lastMessageAt ?? a.createdAt));
    replaceConversations(next);
  }

  async function handleEvent(event: WsEvent) {
    if (event.type === "hello") {
      setOnline(new Set(event.onlineUserIds));
      try {
        const { conversations: list } = await listConversations();
        replaceConversations(list);
        const nextPreviews: Record<string, string> = {};
        for (const conversation of list) {
          if (!conversation.lastMessage) continue;
          const revealed = await revealMessage(conversation.lastMessage, conversation, identityRef.current, user.id);
          nextPreviews[conversation.id] = previewText(revealed);
        }
        setPreviews((current) => ({ ...current, ...nextPreviews }));
      } catch {
        // The socket connected. Keep the chats already on screen if the refresh fails.
      }
      return;
    }
    if (event.type === "presence") {
      setOnline((current) => {
        const next = new Set(current);
        if (event.online) next.add(event.userId);
        else next.delete(event.userId);
        return next;
      });
      return;
    }
    if (event.type === "typing") {
      setTyping((current) => {
        const list = new Set(current[event.conversationId] ?? []);
        if (event.active) list.add(event.userId);
        else list.delete(event.userId);
        return { ...current, [event.conversationId]: [...list] };
      });
      window.clearTimeout(typingTimers.current[`${event.conversationId}:${event.userId}`]);
      if (event.active) {
        typingTimers.current[`${event.conversationId}:${event.userId}`] = window.setTimeout(() => {
          setTyping((current) => ({
            ...current,
            [event.conversationId]: (current[event.conversationId] ?? []).filter((id) => id !== event.userId),
          }));
        }, 2500);
      }
      return;
    }
    if (event.type === "read") {
      replaceConversations(
        conversationsRef.current.map((conversation) =>
          conversation.id === event.conversationId ? { ...conversation, peerLastReadAt: event.lastReadAt } : conversation,
        ),
      );
      return;
    }
    if (event.type === "keys") {
      replaceConversations(
        conversationsRef.current.map((conversation) => {
          const apply = (person: Conversation["peer"]) =>
            person && person.id === event.userId
              ? { ...person, ecdhPublic: event.ecdhPublic, ecdsaPublic: event.ecdsaPublic, keysReady: true }
              : person;
          return {
            ...conversation,
            peer: apply(conversation.peer),
            members: conversation.members.map((member) =>
              member.id === event.userId
                ? { ...member, ecdhPublic: event.ecdhPublic, ecdsaPublic: event.ecdsaPublic, keysReady: true }
                : member,
            ),
          };
        }),
      );
      return;
    }
    if (event.type === "conversation") {
      const incoming = event.conversation;
      const exists = conversationsRef.current.some((item) => item.id === incoming.id);
      const next = exists
        ? conversationsRef.current.map((item) => (item.id === incoming.id ? { ...item, ...incoming } : item))
        : [incoming, ...conversationsRef.current];
      next.sort((a, b) => (b.lastMessageAt ?? b.createdAt).localeCompare(a.lastMessageAt ?? a.createdAt));
      replaceConversations(next);
      return;
    }
    if (event.type === "removed") {
      replaceConversations(conversationsRef.current.filter((item) => item.id !== event.conversationId));
      if (activeIdRef.current === event.conversationId) {
        setActiveId(null);
        setMobileThread(false);
      }
      return;
    }
    if (event.type === "react") {
      setMessages((current) => ({
        ...current,
        [event.conversationId]: (current[event.conversationId] ?? []).map((item) =>
          item.id === event.messageId || item.nonce === event.nonce ? { ...item, reactions: event.reactions } : item,
        ),
      }));
      return;
    }
    if (event.type === "collect") {
      setMessages((current) => ({
        ...current,
        [event.conversationId]: (current[event.conversationId] ?? []).map((item) =>
          item.id === event.messageId || item.nonce === event.nonce ? { ...item, collectsReplies: event.collects } : item,
        ),
      }));
      return;
    }
    if (event.type === "edit") {
      let conversation = conversationsRef.current.find((item) => item.id === event.message.conversationId);
      if (!conversation) {
        const { conversations: list } = await listConversations();
        replaceConversations(list);
        conversation = list.find((item) => item.id === event.message.conversationId);
      }
      if (!conversation) return;
      const revealed = await revealMessage(event.message, conversation, identityRef.current, user.id);
      absorbEdit(event.message.conversationId, revealed);
      return;
    }
    if (event.type === "delete") {
      forgetMessage(event);
      if (typeof event.unreadCount === "number" && activeIdRef.current !== event.conversationId) {
        replaceConversations(
          conversationsRef.current.map((conversation) =>
            conversation.id === event.conversationId ? { ...conversation, unreadCount: event.unreadCount ?? conversation.unreadCount } : conversation,
          ),
        );
      }
      return;
    }
    if (event.type !== "message") return;

    const wasKnown = conversationsRef.current.some((item) => item.id === event.message.conversationId);
    let conversation = conversationsRef.current.find((item) => item.id === event.message.conversationId);
    if (!conversation) {
      const { conversations: list } = await listConversations();
      replaceConversations(list);
      conversation = list.find((item) => item.id === event.message.conversationId);
    }
    if (!conversation) return;
    const revealed = await revealMessage(event.message, conversation, identityRef.current, user.id);
    const already = (messagesRef.current[event.message.conversationId] ?? []).some((item) => item.nonce === revealed.nonce);
    setMessages((current) => ({
      ...current,
      [event.message.conversationId]: mergeMessage(current[event.message.conversationId] ?? [], revealed),
    }));
    setPreviews((current) => ({
      ...current,
      [event.message.conversationId]: previewText(revealed),
    }));
    const viewing = activeIdRef.current === event.message.conversationId && document.hasFocus();
    const mine = event.message.senderId === user.id;
    const next = conversationsRef.current.map((item) => {
      if (item.id !== event.message.conversationId) return item;
      return {
        ...item,
        lastMessageAt: event.message.createdAt,
        lastMessage: event.message,
        unreadCount: viewing || !wasKnown || already || mine ? item.unreadCount : item.unreadCount + 1,
      };
    });
    next.sort((a, b) => (b.lastMessageAt ?? b.createdAt).localeCompare(a.lastMessageAt ?? a.createdAt));
    replaceConversations(next);
    if (!mine && viewing) void markRead(event.message.conversationId, event.message.id).catch(() => undefined);
  }

  async function ensureMessages(conversation: Conversation) {
    if (loadedRef.current.has(conversation.id)) return messagesRef.current[conversation.id] ?? [];
    loadedRef.current.add(conversation.id);
    try {
      const page = await listMessages(conversation.id);
      const revealed = await Promise.all(page.messages.map((message) => revealMessage(message, conversation, identityRef.current, user.id)));
      const merged = [...revealed];
      for (const item of messagesRef.current[conversation.id] ?? []) {
        if (!merged.some((message) => message.nonce === item.nonce)) merged.push(item);
      }
      merged.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      setHasMore((current) => ({ ...current, [conversation.id]: page.hasMore }));
      setMessages((current) => ({ ...current, [conversation.id]: merged }));
      return merged;
    } catch (error) {
      loadedRef.current.delete(conversation.id);
      throw error;
    }
  }

  function noteRead(conversationId: string, items: ChatMessage[]) {
    const incoming = [...items].reverse().find((message) => message.senderId !== user.id && !message.id.startsWith("local:"));
    replaceConversations(conversationsRef.current.map((item) => (item.id === conversationId ? { ...item, unreadCount: 0 } : item)));
    if (incoming) void markRead(conversationId, incoming.id).catch(() => undefined);
  }

  useEffect(() => {
    const onFocus = () => {
      const id = activeIdRef.current;
      if (!id) return;
      noteRead(id, messagesRef.current[id] ?? []);
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [user.id]);

  useEffect(() => {
    if (!actionMenu && !reactMenu) return;
    const close = () => {
      setActionMenu(null);
      setReactMenu(null);
      setEmojiPick("");
    };
    window.addEventListener("pointerdown", close);
    return () => window.removeEventListener("pointerdown", close);
  }, [actionMenu, reactMenu]);

  function selectConversation(conversation: Conversation) {
    if (activeId) {
      draftsRef.current[activeId] = draft;
      editingIdsRef.current[activeId] = editingId;
    }
    if (activeId && typingSent.current) {
      sendSocket({ type: "typing", conversationId: activeId, active: false });
      typingSent.current = false;
    }
    stickRef.current = true;
    if (activeId) repliesRef.current[activeId] = replyTo;
    setActiveId(conversation.id);
    setDraft(draftsRef.current[conversation.id] ?? "");
    setReplyTo(repliesRef.current[conversation.id] ?? null);
    setEditingId(editingIdsRef.current[conversation.id] ?? null);
    setForwardNote("");
    setActionMenu(null);
    setReactMenu(null);
    setEmojiPick("");
    setSelectedNonces([]);
    setShareError("");
    setMobileThread(true);
    setSendError("");
    setPhotoFile(null);
    if (recordingRef.current) cancelRecording();
    void ensureMessages(conversation)
      .then((items) => noteRead(conversation.id, items))
      .catch((error: unknown) => {
        setSendError(error instanceof Error ? error.message : "Couldn't load messages.");
      });
  }

  async function loadEarlier() {
    if (!active || loadingEarlier) return;
    const items = messages[active.id] ?? [];
    const oldest = items[0];
    if (!oldest) return;
    setLoadingEarlier(true);
    const el = scrollerRef.current;
    const previousHeight = el?.scrollHeight ?? 0;
    try {
      const page = await listMessages(active.id, oldest.createdAt);
      const revealed = await Promise.all(page.messages.map((message) => revealMessage(message, active, identity, user.id)));
      setHasMore((current) => ({ ...current, [active.id]: page.hasMore }));
      setMessages((current) => {
        const merged = [...revealed];
        for (const item of current[active.id] ?? []) {
          if (!merged.some((message) => message.nonce === item.nonce)) merged.push(item);
        }
        merged.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
        return { ...current, [active.id]: merged };
      });
      requestAnimationFrame(() => {
        if (el) el.scrollTop = el.scrollHeight - previousHeight;
      });
    } finally {
      setLoadingEarlier(false);
    }
  }

  function updateDraft(value: string) {
    setDraft(value);
    if (!active) return;
    draftsRef.current[active.id] = value;
    const textarea = textareaRef.current;
    if (textarea) {
      textarea.style.height = "auto";
      textarea.style.height = `${Math.min(textarea.scrollHeight, 120)}px`;
    }
    if (!value.trim()) {
      if (typingSent.current) sendSocket({ type: "typing", conversationId: active.id, active: false });
      typingSent.current = false;
      return;
    }
    if (!typingSent.current) {
      typingSent.current = true;
      sendSocket({ type: "typing", conversationId: active.id, active: true });
    }
    window.clearTimeout(typingStop.current);
    typingStop.current = window.setTimeout(() => {
      if (!activeIdRef.current) return;
      typingSent.current = false;
      sendSocket({ type: "typing", conversationId: activeIdRef.current, active: false });
    }, 1500);
  }

  function absorbEdit(conversationId: string, incoming: ChatMessage) {
    const merged = mergeMessage(messagesRef.current[conversationId] ?? [], incoming);
    setMessages((current) => ({ ...current, [conversationId]: mergeMessage(current[conversationId] ?? [], incoming) }));
    const last = merged[merged.length - 1];
    const conversation = conversationsRef.current.find((item) => item.id === conversationId);
    const matchesLast = conversation?.lastMessage?.id === incoming.id || conversation?.lastMessage?.nonce === incoming.nonce;
    const isNewestLoaded = loadedRef.current.has(conversationId) && last?.nonce === incoming.nonce;
    if ((matchesLast || isNewestLoaded) && last) {
      const previewSource = last.nonce === incoming.nonce ? incoming : last;
      setPreviews((current) => ({ ...current, [conversationId]: previewText(previewSource) }));
    }
    if (!matchesLast || !conversation?.lastMessage) return;
    replaceConversations(
      conversationsRef.current.map((item) =>
        item.id === conversationId
          ? {
              ...item,
              lastMessage: {
                ...item.lastMessage!,
                forRecipient: incoming.forRecipient,
                forSender: incoming.forSender,
                signature: incoming.signature,
                editedAt: incoming.editedAt,
              },
            }
          : item,
      ),
    );
  }

  function finishEdit(conversationId: string) {
    const stash = editStashRef.current[conversationId];
    delete editStashRef.current[conversationId];
    editingIdsRef.current[conversationId] = null;
    if (activeIdRef.current !== conversationId) return;
    setEditingId(null);
    const reply = stash?.reply ?? null;
    repliesRef.current[conversationId] = reply;
    setReplyTo(reply);
    updateDraft(stash?.draft ?? "");
  }

  function readyToSeal(conversation: Conversation) {
    if (conversation.kind === "group") return conversation.members.every((member) => member.ecdhPublic);
    return Boolean(conversation.peer?.ecdhPublic);
  }

  async function sealFor(conversation: Conversation, plaintext: string, nonce?: string) {
    if (conversation.kind === "group") {
      if (!readyToSeal(conversation)) throw new Error("Someone in the group hasn't finished setting up encryption yet.");
      return encryptGroupMessage({
        identity,
        conversationId: conversation.id,
        senderId: user.id,
        plaintext,
        nonce,
        members: [
          { userId: user.id, ecdhPublic: identity.ecdhPublic },
          ...conversation.members.map((member) => ({ userId: member.id, ecdhPublic: member.ecdhPublic as string })),
        ],
      });
    }
    if (!conversation.peer?.ecdhPublic) throw new Error("That person hasn't finished setting up encryption yet.");
    return encryptMessage({
      identity,
      recipientEcdhPublic: conversation.peer.ecdhPublic,
      conversationId: conversation.id,
      senderId: user.id,
      plaintext,
      nonce,
    });
  }

  function sealedFields(envelope: Awaited<ReturnType<typeof sealFor>>) {
    if ("copies" in envelope) {
      const copy = envelope.copies.find((item) => item.userId === user.id) ?? envelope.copies[0];
      const bundle = { ephPublic: copy.ephPublic, iv: copy.iv, ciphertext: copy.ciphertext };
      return { nonce: envelope.nonce, forRecipient: bundle, forSender: bundle, forMe: bundle, signature: copy.signature };
    }
    return {
      nonce: envelope.nonce,
      forRecipient: envelope.forRecipient,
      forSender: envelope.forSender,
      forMe: null,
      signature: envelope.signature,
    };
  }

  async function saveEdit() {
    if (!active || !editingId || sending || recording) return;
    const conversation = active;
    const message = (messagesRef.current[conversation.id] ?? []).find((item) => item.id === editingId);
    if (!message || message.senderId !== user.id || message.pending || message.id.startsWith("local:")) return;
    const text = draft.trim();
    if (!text && !message.file) return;
    if (!readyToSeal(conversation)) {
      setSendError(conversation.kind === "group" ? "Someone in the group hasn't finished setting up encryption yet." : "That person hasn't finished setting up encryption yet.");
      return;
    }
    const previousText = message.text;
    const previousEditedAt = message.editedAt;
    setSending(true);
    setSendError("");
    try {
      const plaintext = packPayload({
        text,
        file: message.file,
        reply: message.reply,
        forwarded: message.forwarded,
      });
      const envelope = await sealFor(conversation, plaintext, message.nonce);
      const sealed = sealedFields(envelope);
      absorbEdit(conversation.id, {
        ...message,
        text,
        ...sealed,
        editedAt: new Date().toISOString(),
        failed: false,
      });
      const { message: saved } = await editMessage(conversation.id, message.id, envelope);
      absorbEdit(conversation.id, {
        ...saved,
        text,
        file: message.file,
        reply: message.reply,
        forwarded: message.forwarded,
        localUrl: message.localUrl,
        failed: false,
      });
      finishEdit(conversation.id);
    } catch (error) {
      absorbEdit(conversation.id, { ...message, text: previousText, editedAt: previousEditedAt });
      setSendError(error instanceof Error ? error.message : "Couldn't save that edit.");
    } finally {
      setSending(false);
    }
  }

  async function submitMessage() {
    if (editingId && active && (messagesRef.current[active.id] ?? []).some((item) => item.id === editingId)) {
      await saveEdit();
      return;
    }
    if (!active || sending || recording) return;
    const text = draft;
    const file = pendingFile;
    if (!text.trim() && !file) return;
    if (!readyToSeal(active)) {
      setSendError(active.kind === "group" ? "Someone in the group hasn't finished setting up encryption yet." : "That person hasn't finished setting up encryption yet.");
      return;
    }
    setSending(true);
    setSendError("");
    const quote = replyTo;
    const voiceMs = pendingVoice;
    let localUrl: string | undefined;
    try {
      let attachment: AttachmentMeta | null = null;
      if (file) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        const encrypted = await encryptFile(bytes);
        const digest = await sha256Base64(encrypted.ciphertext);
        const uploaded = await uploadAttachment(active.id, encrypted.ciphertext);
        attachment = {
          id: uploaded.id,
          name: safeFileName(file.name),
          type: file.type || "application/octet-stream",
          size: file.size,
          key: encrypted.key,
          iv: encrypted.iv,
          sha256: digest,
          ...(voiceMs != null ? { voice: true, durationMs: voiceMs } : {}),
        };
        if (isPreviewableImage(attachment.type) || attachment.voice) localUrl = pendingPreview ?? URL.createObjectURL(file);
      }
      const body = text.trim();
      const plaintext = packPayload({ text: body, file: attachment, reply: quote });
      const envelope = await sealFor(active, plaintext);
      const sealed = sealedFields(envelope);
      const optimistic: ChatMessage = {
        id: `local:${sealed.nonce}`,
        conversationId: active.id,
        senderId: user.id,
        createdAt: new Date().toISOString(),
        ...sealed,
        text: body,
        file: attachment,
        reply: quote,
        forwarded: false,
        collectsReplies: false,
        editedAt: null,
        reactions: [],
        localUrl,
        failed: false,
        pending: true,
      };
      setDraft("");
      draftsRef.current[active.id] = "";
      repliesRef.current[active.id] = null;
      setReplyTo(null);
      if (textareaRef.current) textareaRef.current.style.height = "auto";
      if (pendingPreview && pendingPreview !== localUrl) URL.revokeObjectURL(pendingPreview);
      setPendingFile(null);
      setPendingPreview(null);
      setPendingVoice(null);
      if (typingSent.current) sendSocket({ type: "typing", conversationId: active.id, active: false });
      typingSent.current = false;
      setMessages((current) => ({ ...current, [active.id]: mergeMessage(current[active.id] ?? [], optimistic) }));
      setPreviews((current) => ({ ...current, [active.id]: previewText(optimistic) }));
      stickRef.current = true;
      const { message } = await sendMessage(active.id, envelope);
      setMessages((current) => ({
        ...current,
        [active.id]: mergeMessage(current[active.id] ?? [], {
          ...message,
          text: body,
          file: attachment,
          reply: quote,
          forwarded: false,
          localUrl,
          failed: false,
          pending: false,
        }),
      }));
    } catch (error) {
      if (localUrl) URL.revokeObjectURL(localUrl);
      setDraft(text);
      draftsRef.current[active.id] = text;
      repliesRef.current[active.id] = quote;
      setReplyTo(quote);
      setSendError(error instanceof Error ? error.message : "Message wasn't sent.");
    } finally {
      setSending(false);
    }
  }

  function attachReady(file: File | null) {
    if (!file) {
      if (pendingPreview) URL.revokeObjectURL(pendingPreview);
      setPendingFile(null);
      setPendingPreview(null);
      setPendingVoice(null);
      return;
    }
    if (file.size === 0) {
      setSendError("That file is empty.");
      return;
    }
    if (file.size > 8 * 1024 * 1024) {
      setSendError("Files need to be 8 MB or smaller.");
      return;
    }
    if (pendingPreview) URL.revokeObjectURL(pendingPreview);
    setSendError("");
    setPendingVoice(null);
    setPendingFile(file);
    setPendingPreview(isPreviewableImage(file.type) ? URL.createObjectURL(file) : null);
  }

  async function chooseFile(file: File | null) {
    if (!file) {
      attachReady(null);
      return;
    }
    if (file.size === 0) {
      setSendError("That file is empty.");
      return;
    }
    if (file.size > 8 * 1024 * 1024) {
      setSendError("Files need to be 8 MB or smaller.");
      return;
    }
    const photo = await preparePhoto(file);
    if (photo) {
      setSendError("");
      setPhotoFile(photo);
      return;
    }
    attachReady(file);
  }

  function releaseRecording() {
    window.clearInterval(recordTimerRef.current);
    recordStreamRef.current?.getTracks().forEach((track) => track.stop());
    recordStreamRef.current = null;
    mediaRecorderRef.current = null;
    recordingRef.current = false;
    setRecording(false);
    setRecordMs(0);
  }

  function cancelRecording() {
    const recorder = mediaRecorderRef.current;
    if (recorder && recorder.state !== "inactive") {
      discardRecordingRef.current = true;
      recorder.stop();
      return;
    }
    discardRecordingRef.current = false;
    releaseRecording();
  }

  function preferredAudioMime() {
    const types = ["audio/webm;codecs=opus", "audio/webm", "audio/mp4", "audio/ogg"];
    return types.find((type) => MediaRecorder.isTypeSupported(type)) ?? "";
  }

  function acceptVoice(file: File, durationMs: number) {
    if (file.size === 0) {
      setSendError("That voice message is empty.");
      return;
    }
    if (file.size > 8 * 1024 * 1024) {
      setSendError("That voice message is too long.");
      return;
    }
    if (pendingPreview) URL.revokeObjectURL(pendingPreview);
    setSendError("");
    setPendingFile(file);
    setPendingVoice(durationMs);
    setPendingPreview(URL.createObjectURL(file));
  }

  async function startRecording() {
    if (recordStartingRef.current || recordingRef.current || sending || pendingFile) return;
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === "undefined") {
      setSendError("This browser can't record a voice message.");
      return;
    }
    recordStartingRef.current = true;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      recordStreamRef.current = stream;
      const mimeType = preferredAudioMime();
      const recorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
      recordChunksRef.current = [];
      recorder.ondataavailable = (event) => {
        if (event.data.size > 0) recordChunksRef.current.push(event.data);
      };
      recorder.onstop = () => {
        const chunks = recordChunksRef.current.splice(0);
        const durationMs = Math.max(0, Date.now() - recordStartedRef.current);
        const discarded = discardRecordingRef.current;
        discardRecordingRef.current = false;
        const type = recorder.mimeType || mimeType || "audio/webm";
        releaseRecording();
        if (discarded) return;
        if (durationMs < 500 || chunks.length === 0) {
          setSendError("Record a little longer to send a voice message.");
          return;
        }
        const extension = type.includes("mp4") ? "m4a" : type.includes("ogg") ? "ogg" : "webm";
        acceptVoice(new File(chunks, `voice.${extension}`, { type }), durationMs);
      };
      mediaRecorderRef.current = recorder;
      recordStreamRef.current = stream;
      recordStartedRef.current = Date.now();
      discardRecordingRef.current = false;
      recorder.start(200);
      recordingRef.current = true;
      setRecording(true);
      setRecordMs(0);
      setSendError("");
      recordTimerRef.current = window.setInterval(() => {
        const elapsed = Date.now() - recordStartedRef.current;
        setRecordMs(elapsed);
        if (elapsed >= 3 * 60 * 1000 && recorder.state === "recording") recorder.stop();
      }, 200);
    } catch (error) {
      recordStreamRef.current?.getTracks().forEach((track) => track.stop());
      recordStreamRef.current = null;
      const denied = error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "SecurityError");
      setSendError(denied ? "Whisper needs the microphone to record a voice message." : "Couldn't start the recording.");
    } finally {
      recordStartingRef.current = false;
    }
  }

  function stopRecording() {
    const recorder = mediaRecorderRef.current;
    if (recorder && recorder.state === "recording") recorder.stop();
  }

  function onComposerKey(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void submitMessage();
    }
  }

  async function attachPastedPhoto(file: File) {
    if (file.size === 0) {
      setSendError("That file is empty.");
      return;
    }
    if (file.size > 8 * 1024 * 1024) {
      setSendError("Files need to be 8 MB or smaller.");
      return;
    }
    const photo = await preparePhoto(file);
    attachReady(photo ?? file);
  }

  function onComposerPaste(event: ClipboardEvent<HTMLTextAreaElement>) {
    if (recording || editing) return;
    const file = pastedImage(event.clipboardData);
    if (!file) return;
    event.preventDefault();
    void attachPastedPhoto(file);
  }

  function rememberReply(conversationId: string, quote: QuotedMessage | null) {
    repliesRef.current[conversationId] = quote;
    if (activeIdRef.current === conversationId) setReplyTo(quote);
  }

  function beginEdit(message: ChatMessage) {
    if (!active || message.pending || message.id.startsWith("local:") || message.failed || message.senderId !== user.id) return;
    if (recording || pendingFile) {
      setSendError(pendingFile ? "Send or remove the attachment before editing." : "Stop the recording before editing.");
      return;
    }
    setSendError("");
    const existing = editStashRef.current[active.id];
    editStashRef.current[active.id] = existing
      ? { ...existing, messageId: message.id }
      : { messageId: message.id, draft, reply: replyTo };
    editingIdsRef.current[active.id] = message.id;
    setEditingId(message.id);
    repliesRef.current[active.id] = null;
    setReplyTo(null);
    updateDraft(message.text);
    requestAnimationFrame(() => {
      const textarea = textareaRef.current;
      if (!textarea) return;
      textarea.focus();
      textarea.style.height = "auto";
      textarea.style.height = `${Math.min(textarea.scrollHeight, 120)}px`;
    });
  }

  function cancelEdit() {
    if (!active) return;
    const stash = editStashRef.current[active.id];
    delete editStashRef.current[active.id];
    editingIdsRef.current[active.id] = null;
    setEditingId(null);
    const reply = stash?.reply ?? null;
    repliesRef.current[active.id] = reply;
    setReplyTo(reply);
    updateDraft(stash?.draft ?? "");
  }

  async function copyMessage(message: ChatMessage) {
    const text = message.text.trim() || (message.file ? fileLabel(message.file) : "");
    const photo = message.file && isPreviewableImage(message.file.type) ? message.file : null;
    if (!text && !photo) return;
    setActionMenu(null);
    if (photo && typeof ClipboardItem !== "undefined" && navigator.clipboard?.write) {
      try {
        const png = photoPngBlob(message);
        await navigator.clipboard.write([new ClipboardItem({ "image/png": png })]);
        markCopied(message.nonce);
        return;
      } catch {
        // The photo could not be placed on the clipboard, so copy its caption instead.
      }
    }
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.left = "-9999px";
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    markCopied(message.nonce);
  }

  function markCopied(nonce: string) {
    setCopiedNonce(nonce);
    window.setTimeout(() => setCopiedNonce((current) => (current === nonce ? null : current)), 1500);
  }

  function beginReply(message: ChatMessage) {
    if (editingId) cancelEdit();
    if (!active || message.failed || (!message.text.trim() && !message.file)) return;
    const quote: QuotedMessage = {
      id: message.nonce,
      senderId: message.senderId,
      sender: personName(active, message.senderId, user.id),
      preview: previewText({ ...message, forwarded: false }).slice(0, 160) || "Message",
    };
    rememberReply(active.id, quote);
    textareaRef.current?.focus();
  }

  function canSelect(message: ChatMessage) {
    return !message.failed && Boolean(message.text.trim() || message.file);
  }

  function clearSelection() {
    setSelectedNonces([]);
    setShareError("");
  }

  function toggleSelected(message: ChatMessage) {
    if (!canSelect(message)) return;
    setShareError("");
    setSelectedNonces((current) => {
      if (current.includes(message.nonce)) return current.filter((nonce) => nonce !== message.nonce);
      if (current.length >= 20) {
        setShareError("You can select up to 20 messages.");
        return current;
      }
      return [...current, message.nonce];
    });
  }

  function beginSelect(message: ChatMessage) {
    if (!canSelect(message)) return;
    setActionMenu(null);
    setReactMenu(null);
    setShareError("");
    setSelectedNonces([message.nonce]);
  }

  function beginForward(messages: ChatMessage[]) {
    const sources = messages.filter(canSelect);
    if (sources.length === 0) return;
    setForwardSources(sources);
    setForwardLookup("");
    setForwardError("");
    setDialog("forward");
  }

  function beginDelete(message: ChatMessage) {
    if (message.pending || message.id.startsWith("local:")) return;
    setDeleteTarget(message);
    setDeleteError("");
    setDialog("delete");
  }

  async function reactTo(message: ChatMessage, emoji: string) {
    if (message.pending || message.id.startsWith("local:") || !active) return;
    setActionMenu(null);
    setReactMenu(null);
    const mine = (message.reactions ?? []).find((reaction) => reaction.userId === user.id);
    const next = mine?.emoji === emoji ? null : emoji;
    const previous = message.reactions ?? [];
    const optimistic = next
      ? [...previous.filter((reaction) => reaction.userId !== user.id), { userId: user.id, emoji: next }]
      : previous.filter((reaction) => reaction.userId !== user.id);
    const apply = (reactions: MessageReaction[]) => {
      setMessages((current) => ({
        ...current,
        [message.conversationId]: (current[message.conversationId] ?? []).map((item) =>
          item.nonce === message.nonce ? { ...item, reactions } : item,
        ),
      }));
    };
    apply(optimistic);
    try {
      const saved = await setReaction(message.conversationId, message.id, next);
      apply(saved.reactions);
    } catch {
      apply(previous);
    }
  }

  async function toggleCollect(message: ChatMessage) {
    if (message.pending || message.id.startsWith("local:")) return;
    const collects = !message.collectsReplies;
    setMessages((current) => ({
      ...current,
      [message.conversationId]: (current[message.conversationId] ?? []).map((item) =>
        item.nonce === message.nonce ? { ...item, collectsReplies: collects } : item,
      ),
    }));
    try {
      await setCollectsReplies(message.conversationId, message.id, collects);
    } catch (error) {
      setMessages((current) => ({
        ...current,
        [message.conversationId]: (current[message.conversationId] ?? []).map((item) =>
          item.nonce === message.nonce ? { ...item, collectsReplies: message.collectsReplies } : item,
        ),
      }));
      setSendError(error instanceof Error ? error.message : "Couldn't update that message.");
    }
  }

  async function confirmDelete() {
    if (!deleteTarget || deleting) return;
    setDeleting(true);
    setDeleteError("");
    try {
      const result = await deleteMessage(deleteTarget.conversationId, deleteTarget.id, deleteTarget.file?.id);
      forgetMessage({
        conversationId: deleteTarget.conversationId,
        messageId: deleteTarget.id,
        nonce: deleteTarget.nonce,
        lastMessageAt: result.lastMessageAt,
      });
      setDialog(null);
      setDeleteTarget(null);
    } catch (error) {
      setDeleteError(error instanceof Error ? error.message : "Couldn't delete that message.");
    } finally {
      setDeleting(false);
    }
  }

  function noteForwarded(name: string, count = 1) {
    setForwardNote(count > 1 ? `Forwarded ${count} messages to ${name}` : `Forwarded to ${name}`);
    window.clearTimeout(forwardNoteTimer.current);
    forwardNoteTimer.current = window.setTimeout(() => setForwardNote(""), 4000);
  }

  async function forwardOne(target: Conversation, source: ChatMessage) {
    let attachment: AttachmentMeta | null = null;
    if (source.file) {
      const bytes = await decryptAttachment(source.conversationId, source.file);
      const encrypted = await encryptFile(bytes);
      const digest = await sha256Base64(encrypted.ciphertext);
      const uploaded = await uploadAttachment(target.id, encrypted.ciphertext);
      attachment = {
        id: uploaded.id,
        name: source.file.name,
        type: source.file.type,
        size: source.file.size,
        key: encrypted.key,
        iv: encrypted.iv,
        sha256: digest,
        ...(source.file.voice ? { voice: true, durationMs: source.file.durationMs } : {}),
      };
    }
    const envelope = await sealFor(target, packPayload({ text: source.text.trim(), file: attachment, forwarded: true }));
    const { message } = await sendMessage(target.id, envelope);
    const revealed: ChatMessage = {
      ...message,
      text: source.text.trim(),
      file: attachment,
      reply: null,
      forwarded: true,
      failed: false,
    };
    setMessages((current) => ({ ...current, [target.id]: mergeMessage(current[target.id] ?? [], revealed) }));
    setPreviews((current) => ({ ...current, [target.id]: previewText(revealed) }));
    const next = conversationsRef.current.map((item) =>
      item.id === target.id ? { ...item, lastMessageAt: message.createdAt, lastMessage: message } : item,
    );
    if (!next.some((item) => item.id === target.id)) {
      next.unshift({ ...target, lastMessageAt: message.createdAt, lastMessage: message, unreadCount: 0 });
    }
    next.sort((a, b) => (b.lastMessageAt ?? b.createdAt).localeCompare(a.lastMessageAt ?? a.createdAt));
    replaceConversations(next);
    if (activeIdRef.current === target.id) stickRef.current = true;
  }

  async function deliverForward(target: Conversation) {
    const sources = [...forwardSources].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    if (sources.length === 0 || forwarding) return;
    if (!readyToSeal(target)) {
      setForwardError(target.kind === "group" ? "Someone in the group hasn't finished setting up encryption yet." : "That person hasn't finished setting up encryption yet.");
      return;
    }
    setForwarding(true);
    setForwardError("");
    let sent = 0;
    try {
      for (const source of sources) {
        await forwardOne(target, source);
        sent += 1;
      }
      setDialog(null);
      setForwardSources([]);
      clearSelection();
      noteForwarded(chatTitle(target), sources.length);
    } catch (error) {
      const remaining = sources.slice(sent);
      setForwardSources(remaining);
      setForwardError(
        sent > 0
          ? `Sent ${sent}. ${error instanceof Error ? error.message : "The rest weren't forwarded."}`
          : error instanceof Error ? error.message : "Couldn't forward that message.",
      );
    } finally {
      setForwarding(false);
    }
  }

  async function messageFile(message: ChatMessage) {
    if (!message.file) return null;
    let blob: Blob;
    if (message.localUrl) {
      try {
        blob = await (await fetch(message.localUrl)).blob();
      } catch {
        blob = await decryptedBlob(message.conversationId, message.file);
      }
    } else {
      blob = await decryptedBlob(message.conversationId, message.file);
    }
    const type = message.file.voice ? playbackType(message.file.type) : blob.type || message.file.type || "application/octet-stream";
    return new File([blob], safeFileName(message.file.name), { type });
  }

  function shareLines(conversation: Conversation, messages: ChatMessage[]) {
    return messages.map((message) => {
      const who = personName(conversation, message.senderId, user.id);
      const caption = message.text.replace(/\s+/g, " ").trim();
      const label = message.file ? fileLabel(message.file) : "";
      return `${who}: ${caption || label}`;
    }).filter((line) => !line.endsWith(": "));
  }

  async function shareMessages(messages: ChatMessage[]) {
    const sources = [...messages].filter(canSelect).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    if (sources.length === 0 || sharing || !active) return;
    const fromSelection = selectedNonces.length > 0;
    const report = (message: string) => {
      if (fromSelection) setShareError(message);
      else setSendError(message);
    };
    setSharing(true);
    setShareError("");
    if (!fromSelection) setSendError("");
    setActionMenu(null);
    const text = shareLines(active, sources).join("\n");
    try {
      const files: File[] = [];
      for (const source of sources) {
        const file = await messageFile(source);
        if (file) files.push(file);
      }
      if (!text && files.length === 0) return;
      if (typeof navigator.share === "function") {
        const withFiles = { text, files };
        if (files.length > 0 && navigator.canShare?.(withFiles)) {
          await navigator.share(withFiles);
        } else if (text) {
          await navigator.share({ text });
          if (files.length > 0) setSendError("The text was shared. This device couldn't attach the files.");
        } else {
          await navigator.share({ files });
        }
        clearSelection();
        return;
      }
      if (text) {
        await navigator.clipboard.writeText(text);
        report("This device has no share sheet, so the text was copied.");
        return;
      }
      report("This device can't share files to another app.");
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      if (text) {
        try {
          await navigator.clipboard.writeText(text);
          report("Couldn't open the share sheet, so the text was copied.");
          return;
        } catch {
          // Fall through to the generic error.
        }
      }
      report(error instanceof Error ? error.message : "Couldn't share those messages.");
    } finally {
      setSharing(false);
    }
  }

  async function forwardToUsername(event: FormEvent) {
    event.preventDefault();
    const username = forwardLookup.trim().toLowerCase();
    if (!username || forwarding) return;
    const existing = conversationsRef.current.find((conversation) => conversation.kind === "direct" && conversation.peer?.username === username);
    if (existing) {
      await deliverForward(existing);
      return;
    }
    setForwarding(true);
    setForwardError("");
    try {
      const { users } = await searchUsers(username);
      const match = users.find((person) => person.username === username)
        ?? users.find((person) => person.displayName.toLowerCase() === username);
      if (!match) {
        setForwardError("No one uses that username.");
        setForwarding(false);
        return;
      }
      if (!match.keysReady || !match.ecdhPublic) {
        setForwardError("That person hasn't finished setting up encryption yet.");
        setForwarding(false);
        return;
      }
      const { conversation } = await openConversation(match.username);
      const next = [conversation, ...conversationsRef.current.filter((item) => item.id !== conversation.id)];
      replaceConversations(next);
      setForwarding(false);
      await deliverForward(conversation);
    } catch (error) {
      setForwardError(error instanceof Error ? error.message : "Couldn't forward that message.");
      setForwarding(false);
    }
  }

  async function startChat(event: FormEvent) {
    event.preventDefault();
    const username = lookup.trim().toLowerCase();
    setLookupError("");
    try {
      const { users } = await searchUsers(username);
      const match = users.find((person) => person.username === username)
        ?? users.find((person) => person.displayName.toLowerCase() === username);
      if (!match) {
        setLookupError("No one uses that username.");
        return;
      }
      if (!match.keysReady || !match.ecdhPublic) {
        setLookupError("That person hasn't finished setting up encryption yet.");
        return;
      }
      await openWithPerson(match.username);
    } catch (error) {
      setLookupError(error instanceof Error ? error.message : "Couldn't start the chat.");
    }
  }

  async function openWithPerson(username: string) {
    const { conversation } = await openConversation(username);
    const next = [conversation, ...conversationsRef.current.filter((item) => item.id !== conversation.id)];
    replaceConversations(next);
    setDialog(null);
    setLookup("");
    selectConversation(conversation);
  }

  async function changePassword(event: FormEvent) {
    event.preventDefault();
    if (passwordNext.length < 8) {
      setPasswordError("Use at least 8 characters.");
      return;
    }
    if (passwordNext !== passwordConfirm) {
      setPasswordError("Those passwords don't match.");
      return;
    }
    if (passwordNext === passwordCurrent) {
      setPasswordError("Choose a different password.");
      return;
    }
    setPasswordBusy(true);
    setPasswordError("");
    try {
      const authVerifier = await deriveAuthVerifier(user.username, passwordCurrent);
      const nextAuthVerifier = await deriveAuthVerifier(user.username, passwordNext);
      const wrapped = await wrapIdentity(identity, passwordNext);
      const saved = await changePasswordRequest({ ...wrapped, authVerifier, nextAuthVerifier });
      onAccount(saved.user, identity);
      setDialog(null);
      setPasswordCurrent("");
      setPasswordNext("");
      setPasswordConfirm("");
    } catch (error) {
      setPasswordError(error instanceof Error ? error.message : "Couldn't change the password.");
    } finally {
      setPasswordBusy(false);
    }
  }

  async function replaceKeys(event: FormEvent) {
    event.preventDefault();
    if (resetSecret.length < 8) {
      setResetError("Use at least 8 characters.");
      return;
    }
    if (user.provider === "google" && resetSecret !== resetConfirm) {
      setResetError("Those passphrases don't match.");
      return;
    }
    if (!resetUnderstood) {
      setResetError("Confirm that older messages will stay unreadable.");
      return;
    }
    setResetBusy(true);
    setResetError("");
    try {
      if (user.provider === "password") await confirmPassword(await deriveAuthVerifier(user.username, resetSecret));
      const nextIdentity = await generateIdentity();
      const wrapped = await wrapIdentity(nextIdentity, resetSecret);
      const saved = await resetKeysRequest(wrapped);
      await saveIdentity(saved.user.id, nextIdentity);
      onAccount(saved.user, nextIdentity);
      setDialog(null);
      setResetSecret("");
      setResetConfirm("");
      setResetUnderstood(false);
    } catch (error) {
      setResetError(error instanceof Error ? error.message : "Couldn't replace the keys.");
    } finally {
      setResetBusy(false);
    }
  }

  function addPlannedMember(event: { preventDefault(): void }) {
    event.preventDefault();
    const username = groupUser.trim().toLowerCase();
    if (!username) return;
    if (username === user.username) {
      setGroupError("You're already included.");
      return;
    }
    if (groupMembers.includes(username)) {
      setGroupUser("");
      return;
    }
    if (groupMembers.length >= 15) {
      setGroupError("A group can hold 16 people, including you.");
      return;
    }
    setGroupMembers((current) => [...current, username]);
    setGroupUser("");
    setGroupError("");
  }

  async function startGroup(event: FormEvent) {
    event.preventDefault();
    const title = groupTitle.trim();
    if (!title || groupMembers.length < 2 || groupBusy) return;
    setGroupBusy(true);
    setGroupError("");
    try {
      const { conversation } = await createGroup(title, groupMembers);
      replaceConversations([conversation, ...conversationsRef.current.filter((item) => item.id !== conversation.id)]);
      setDialog(null);
      setGroupTitle("");
      setGroupMembers([]);
      setGroupUser("");
      selectConversation(conversation);
    } catch (error) {
      setGroupError(error instanceof Error ? error.message : "Couldn't create the group.");
    } finally {
      setGroupBusy(false);
    }
  }

  async function inviteMember(event: FormEvent) {
    event.preventDefault();
    if (!active || active.kind !== "group" || groupBusy) return;
    const username = groupUser.trim().toLowerCase();
    if (!username) return;
    setGroupBusy(true);
    setGroupError("");
    try {
      const { conversation } = await addGroupMember(active.id, username);
      replaceConversations(conversationsRef.current.map((item) => (item.id === conversation.id ? conversation : item)));
      setGroupUser("");
    } catch (error) {
      setGroupError(error instanceof Error ? error.message : "Couldn't add that person.");
    } finally {
      setGroupBusy(false);
    }
  }

  async function removeMember(userId: string) {
    if (!active || active.kind !== "group" || active.viewerRole !== "admin" || groupBusy) return;
    setGroupBusy(true);
    setGroupError("");
    try {
      const { conversation } = await removeGroupMember(active.id, userId);
      replaceConversations(conversationsRef.current.map((item) => (item.id === conversation.id ? conversation : item)));
    } catch (error) {
      setGroupError(error instanceof Error ? error.message : "Couldn't remove that person.");
    } finally {
      setGroupBusy(false);
    }
  }

  async function leaveCurrentGroup() {
    if (!active || active.kind !== "group" || groupBusy) return;
    setGroupBusy(true);
    setGroupError("");
    try {
      await leaveGroup(active.id);
      replaceConversations(conversationsRef.current.filter((item) => item.id !== active.id));
      setActiveId(null);
      setMobileThread(false);
      setDialog(null);
    } catch (error) {
      setGroupError(error instanceof Error ? error.message : "Couldn't leave the group.");
    } finally {
      setGroupBusy(false);
    }
  }

  async function openHit(hit: SearchHit) {
    const conversation = conversationsRef.current.find((item) => item.id === hit.conversationId);
    if (!conversation) return;
    selectConversation(conversation);
    let items = messagesRef.current[conversation.id] ?? [];
    if (items.length === 0) {
      try {
        items = await ensureMessages(conversation);
      } catch {
        return;
      }
    }
    let guard = 0;
    while (!items.some((item) => item.nonce === hit.nonce) && guard < 15) {
      const oldest = items[0];
      if (!oldest) break;
      const page = await listMessages(conversation.id, oldest.createdAt);
      if (page.messages.length === 0) break;
      const revealed = await Promise.all(
        page.messages.map((message) => revealMessage(message, conversation, identityRef.current, user.id)),
      );
      const merged = [...revealed];
      for (const item of items) {
        if (!merged.some((message) => message.nonce === item.nonce)) merged.push(item);
      }
      merged.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      items = merged;
      setMessages((current) => ({ ...current, [conversation.id]: merged }));
      setHasMore((current) => ({ ...current, [conversation.id]: page.hasMore }));
      if (!page.hasMore) break;
      guard += 1;
    }
    const byNonce = new Map(items.map((item) => [item.nonce, item]));
    const message = byNonce.get(hit.nonce);
    if (message) {
      const collector = collectorNonce(message, byNonce);
      if (collector) setOpenFolders((current) => ({ ...current, [collector]: true }));
    }
    window.setTimeout(() => focusQuoted(hit.nonce), 80);
  }

  useEffect(() => {
    const needle = wordQuery.trim().toLowerCase();
    if (!needle) {
      setHits([]);
      setSearching(false);
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      setSearching(true);
      void searchConversations(conversationsRef.current, wordQuery, wordPhrase, identityRef.current, user.id, () => cancelled)
        .then((found) => {
          if (!cancelled) {
            setHits(found);
            setSearching(false);
          }
        })
        .catch(() => {
          if (!cancelled) setSearching(false);
        });
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [wordQuery, wordPhrase, conversations, user.id]);

  useEffect(() => {
    const needle = chatQuery.trim().toLowerCase();
    const conversationId = activeId;
    if (!needle || !conversationId) {
      setChatHits([]);
      setChatSearching(false);
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      const conversation = conversationsRef.current.find((item) => item.id === conversationId);
      if (!conversation) {
        if (!cancelled) {
          setChatHits([]);
          setChatSearching(false);
        }
        return;
      }
      setChatSearching(true);
      void searchConversations([conversation], chatQuery, chatPhrase, identityRef.current, user.id, () => cancelled)
        .then((found) => {
          if (!cancelled) {
            setChatHits(found);
            setChatSearching(false);
          }
        })
        .catch(() => {
          if (!cancelled) setChatSearching(false);
        });
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [chatQuery, chatPhrase, activeId, user.id]);

  const visible = conversations.filter((conversation) => matchesChat(conversation, userQuery, userPhrase));
  const userLookup = userQuery.trim();
  const wordLookup = wordQuery.trim();

  return (
    <main className={mobileThread ? "app-shell thread-open" : "app-shell"}>
      <aside className="sidebar">
        <header className="side-head">
          <button type="button" className="you" onClick={() => { setShowFingerprint(false); setDialog("profile"); }}>
            <Avatar name={user.displayName} username={user.username} />
            <span>
              <strong>{user.displayName}</strong>
              <small>@{user.username}</small>
            </span>
          </button>
          <button type="button" className="text add-chat" onClick={() => { setDialog("new"); setLookupError(""); }}>
            Add new chat
          </button>
        </header>
        <div className="side-search">
          <label className="search-line">
            <input value={userQuery} onChange={(event) => setUserQuery(event.target.value)} placeholder="Name or username" aria-label="Name or username" />
            <button type="button" className={userPhrase ? "phrase on" : "phrase"} aria-pressed={userPhrase} onClick={() => setUserPhrase((current) => !current)}>
              Search
            </button>
          </label>
        </div>
        {listError && <p className="error inset">{listError}</p>}
        <div className="chat-list">
          {!userLookup && visible.length === 0 && <p className="empty-list">No chats yet. Start one with a username.</p>}
          {userLookup && visible.length === 0 && <p className="empty-list">No users match that search.</p>}
          {visible.map((conversation) => {
            const title = chatTitle(conversation);
            const group = conversation.kind === "group";
            const someoneTyping = (typing[conversation.id]?.length ?? 0) > 0;
            return (
            <button
              type="button"
              key={conversation.id}
              className={conversation.id === activeId ? "chat-row active" : "chat-row"}
              onClick={() => selectConversation(conversation)}
            >
              <Avatar name={title} username={group ? conversation.id : conversation.peer?.username || title} online={!group && conversation.peer ? online.has(conversation.peer.id) : false} />
              <span className="chat-copy">
                <span className="chat-topline">
                  <strong>{title}</strong>
                  {conversation.lastMessageAt && <time>{formatListTime(conversation.lastMessageAt)}</time>}
                </span>
                <span className="chat-bottom">
                  <em>{someoneTyping ? "typing…" : previews[conversation.id] || "Encrypted chat"}</em>
                  {conversation.unreadCount > 0 && <span className="unread">{conversation.unreadCount}</span>}
                </span>
              </span>
            </button>
            );
          })}
        </div>
      </aside>
      <section className="thread">
        {active ? (
          <>
            <header className="thread-head">
              <button type="button" className="back" onClick={() => setMobileThread(false)} aria-label="Back to chats">
                ←
              </button>
              <Avatar
                name={chatTitle(active)}
                username={active.kind === "group" ? active.id : active.peer?.username || chatTitle(active)}
                online={active.kind !== "group" && active.peer ? online.has(active.peer.id) : false}
              />
              <span>
                <strong>{chatTitle(active)}</strong>
                <small>
                  {(typing[active.id]?.length ?? 0) > 0
                    ? active.kind === "group"
                      ? `${(typing[active.id] ?? []).map((id) => personName(active, id, user.id)).filter((name) => name !== "You").join(", ") || "Someone"} typing…`
                      : "typing…"
                    : active.kind === "group"
                      ? `${active.members.length + 1} people · encrypted`
                      : active.peer && online.has(active.peer.id)
                        ? "Online · encrypted"
                        : "Encrypted"}
                </small>
              </span>
              {active.kind === "group" ? (
                <button
                  type="button"
                  className="icon-button"
                  aria-label="People"
                  onClick={() => {
                    setGroupError("");
                    setGroupUser("");
                    setDialog("people");
                  }}
                >
                  <PeopleGlyph />
                </button>
              ) : (
                <button type="button" className="icon-button" aria-label="Safety number" onClick={() => setDialog("safety")}>
                  <LockGlyph />
                </button>
              )}
            </header>
            <div className="chat-search">
              {chatQuery.trim() && (
                <div className="word-hits">
                  {chatSearching && <p className="empty-list">Searching this chat…</p>}
                  {chatHits.map((hit) => (
                    <button type="button" key={hit.nonce} className="chat-row search-hit" onClick={() => void openHit(hit)}>
                      <span className="chat-copy">
                        <em>{hit.snippet}</em>
                      </span>
                    </button>
                  ))}
                  {!chatSearching && chatHits.length === 0 && <p className="empty-list">No messages in this chat match that search.</p>}
                </div>
              )}
              <label className="search-line">
                <input value={chatQuery} onChange={(event) => setChatQuery(event.target.value)} placeholder="Search this chat" aria-label="Search this chat" />
                <button type="button" className={chatPhrase ? "phrase on" : "phrase"} aria-pressed={chatPhrase} onClick={() => setChatPhrase((current) => !current)}>
                  Search
                </button>
              </label>
            </div>
            <div
              className="messages"
              ref={scrollerRef}
              onScroll={() => {
                const el = scrollerRef.current;
                if (!el) return;
                stickRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
              }}
            >
              {hasMore[active.id] && (
                <button type="button" className="text earlier" onClick={() => void loadEarlier()} disabled={loadingEarlier}>
                  {loadingEarlier ? "Loading…" : "Earlier messages"}
                </button>
              )}
              <p className="cipher-note">Messages are end-to-end encrypted. Whisper stores ciphertext, and this browser decrypts it.</p>
              {activeMessages.length === 0 && <p className="empty-thread">Say hello. The text is encrypted before it leaves this browser.</p>}
              {(() => {
                const byNonce = new Map(activeMessages.map((item) => [item.nonce, item]));
                const visible = activeMessages.filter((item) => collectorNonce(item, byNonce) === null);
                const renderBubble = (message: ChatMessage, nested: boolean, menuUp: boolean) => {
                  const mine = message.senderId === user.id;
                  const read = Boolean(active.peerLastReadAt && message.createdAt <= active.peerLastReadAt);
                  const canAct = !message.failed && Boolean(message.text.trim() || message.file);
                  const saved = !message.pending && !message.id.startsWith("local:");
                  const canDelete = mine && saved;
                  const canEdit = mine && saved && !message.failed;
                  const gathered = message.collectsReplies ? repliesFor(message.nonce, activeMessages, byNonce) : [];
                  const open = Boolean(openFolders[message.nonce]);
                  const showActions = canAct || canDelete || canEdit || saved || (!message.failed && Boolean(message.text.trim() || message.file));
                  const canReact = !message.failed && !message.pending && !message.id.startsWith("local:");
                  const picking = selectedNonces.length > 0;
                  const picked = selectedNonces.includes(message.nonce);
                  return (
                    <div
                      className={`select-line ${mine ? "out" : "in"}${picked ? " picked" : ""}${picking ? " picking" : ""}`}
                      onClick={picking ? (event) => {
                        event.stopPropagation();
                        toggleSelected(message);
                      } : undefined}
                    >
                    {picking && (
                      <button
                        type="button"
                        className={picked ? "pick on" : "pick"}
                        aria-pressed={picked}
                        aria-label={picked ? "Deselect message" : "Select message"}
                        onClick={(event) => {
                          event.stopPropagation();
                          toggleSelected(message);
                        }}
                      >
                        {picked ? "✓" : ""}
                      </button>
                    )}
                    <article
                      id={`msg-${message.nonce}`}
                      className={`message-row ${mine ? "out" : "in"}${message.id === editingId ? " editing" : ""}${menuUp ? " menu-up" : ""}`}
                      onContextMenu={(event) => {
                        if (!canSelect(message)) return;
                        event.preventDefault();
                        if (selectedNonces.length === 0) beginSelect(message);
                      }}
                    >
                      <div className={`bubble ${mine ? "out" : "in"}`}>
                      {active.kind === "group" && !mine && !message.failed && (
                        <p className="sender-name">{personName(active, message.senderId, user.id)}</p>
                      )}
                      <div className="bubble-line">
                      <div className="bubble-copy">
                      {message.failed ? (
                        <p>Unable to decrypt this message.</p>
                      ) : (
                        <>
                          {message.forwarded && <p className="forwarded-label">Forwarded</p>}
                          {message.reply && !nested && (
                            <button type="button" className="quote" onClick={() => focusQuoted(message.reply!.id)}>
                              <strong>{quoteLabel(message.reply, user.id)}</strong>
                              <span>{shownQuote(message.reply, byNonce)}</span>
                            </button>
                          )}
                          {message.file && (
                            <AttachmentCard conversationId={message.conversationId} file={message.file} localUrl={message.localUrl} />
                          )}
                          {message.text && <p>{message.text}</p>}
                        </>
                      )}
                      </div>
                      {showActions && !picking && (
                        <span className="message-tools" onPointerDown={(event) => event.stopPropagation()}>
                          <button
                            type="button"
                            className="dots"
                            aria-label="Message actions"
                            aria-expanded={actionMenu === message.nonce}
                            onClick={() => {
                              setReactMenu(null);
                              setActionMenu((current) => (current === message.nonce ? null : message.nonce));
                            }}
                          >
                            <DotsGlyph />
                          </button>
                          {actionMenu === message.nonce && (
                        <span className="bubble-actions" role="menu">
                          {!message.failed && Boolean(message.text.trim() || message.file) && (
                                <button type="button" role="menuitem" onClick={() => void copyMessage(message)}>Copy</button>
                              )}
                              {canAct && (
                                <>
                                  <button type="button" role="menuitem" onClick={() => { setActionMenu(null); beginReply(message); }}>Reply</button>
                                  <button type="button" role="menuitem" onClick={() => { setActionMenu(null); beginForward([message]); }}>Forward</button>
                                  <button type="button" role="menuitem" onClick={() => beginSelect(message)}>Select</button>
                                  <button type="button" role="menuitem" onClick={() => void shareMessages([message])}>Share</button>
                                </>
                              )}
                              {canEdit && (
                                <button type="button" role="menuitem" onClick={() => { setActionMenu(null); beginEdit(message); }}>Edit</button>
                              )}
                              {saved && (
                                <button type="button" role="menuitem" onClick={() => { setActionMenu(null); void toggleCollect(message); }}>
                                  {message.collectsReplies ? "Stop collecting" : "Collect replies"}
                                </button>
                              )}
                              {canDelete && (
                                <button type="button" role="menuitem" className="danger" onClick={() => { setActionMenu(null); beginDelete(message); }}>Delete</button>
                              )}
                            </span>
                          )}
                        </span>
                      )}
                      </div>
                      {message.collectsReplies && (
                        <>
                          <button
                            type="button"
                            className={open ? "folder-toggle open" : "folder-toggle"}
                            aria-expanded={open}
                            aria-label={open ? "Hide replies" : "Show replies"}
                            onClick={() => setOpenFolders((current) => ({ ...current, [message.nonce]: !current[message.nonce] }))}
                          >
                            <FolderFace conversationId={message.conversationId} replies={gathered} />
                            <span>
                              <strong>{gathered.length === 1 ? "1 reply" : `${gathered.length} replies`}</strong>
                              <em>{open ? "Hide" : "Open"}</em>
                            </span>
                          </button>
                          {open && (
                            <div className="folder-replies">
                              {gathered.length === 0 && <p className="folder-empty">Replies will gather here.</p>}
                              {gathered.map((reply, replyIndex) => (
                                <Fragment key={reply.nonce}>{renderBubble(reply, true, menuUp && replyIndex === gathered.length - 1)}</Fragment>
                              ))}
                            </div>
                          )}
                        </>
                      )}
                      <span className="bubble-meta">
                        {copiedNonce === message.nonce && <span className="copied">Copied</span>}
                        {message.editedAt && <span className="edited">edited</span>}
                        <time>{formatTime(message.createdAt)}</time>
                        {mine && <span className={read ? "ticks read" : "ticks"}>{message.pending ? "…" : read ? "✓✓" : "✓"}</span>}
                      </span>
                      </div>
                      {(message.reactions ?? []).length > 0 && (
                        <span className="reaction-chips">
                          {reactionGroups(message.reactions).map((group) => (
                            <button
                              type="button"
                              key={group.emoji}
                              className={group.userIds.includes(user.id) ? "mine" : ""}
                              onClick={() => void reactTo(message, group.emoji)}
                            >
                              {group.emoji}{group.userIds.length > 1 ? ` ${group.userIds.length}` : ""}
                            </button>
                          ))}
                        </span>
                      )}
                      {canReact && !picking && (
                        <span className="react-tools" onPointerDown={(event) => event.stopPropagation()}>
                          <button
                            type="button"
                            className="react-open"
                            aria-label="React"
                            aria-expanded={reactMenu === message.nonce}
                            onClick={() => {
                              setActionMenu(null);
                              setReactMenu((current) => (current === message.nonce ? null : message.nonce));
                            }}
                          >
                            ☺
                          </button>
                          {reactMenu === message.nonce && (
                            <span className="react-row">
                              {REACTION_EMOJI.map((emoji) => (
                                <button
                                  type="button"
                                  key={emoji}
                                  className={(message.reactions ?? []).some((reaction) => reaction.userId === user.id && reaction.emoji === emoji) ? "on" : ""}
                                  aria-label={`React with ${emoji}`}
                                  onClick={() => void reactTo(message, emoji)}
                                >
                                  {emoji}
                                </button>
                              ))}
                              <button
                                type="button"
                                className="react-more"
                                aria-label="Another emoji"
                                aria-expanded={emojiPick === message.nonce}
                                onClick={() => {
                                  setEmojiDraft("");
                                  setEmojiPick((current) => (current === message.nonce ? "" : message.nonce));
                                }}
                              >
                                +
                              </button>
                              {emojiPick === message.nonce && (
                                <input
                                  value={emojiDraft}
                                  aria-label="Type an emoji"
                                  autoFocus
                                  onChange={(event) => {
                                    const emoji = singleEmoji(event.target.value);
                                    if (!emoji) {
                                      setEmojiDraft(event.target.value.slice(0, 16));
                                      return;
                                    }
                                    setEmojiDraft("");
                                    setEmojiPick("");
                                    void reactTo(message, emoji);
                                  }}
                                />
                              )}
                            </span>
                          )}
                        </span>
                      )}
                    </article>
                    </div>
                  );
                };
                return visible.map((message, index) => {
                  const previous = visible[index - 1];
                  return (
                    <Fragment key={message.nonce}>
                      {(!previous || !sameDay(previous.createdAt, message.createdAt)) && <p className="day">{dayLabel(message.createdAt)}</p>}
                      {renderBubble(message, false, index === visible.length - 1)}
                    </Fragment>
                  );
                });
              })()}
            </div>
            <input
              ref={fileInputRef}
              className="sr"
              type="file"
              onChange={(event) => {
                const file = event.target.files?.[0] ?? null;
                event.target.value = "";
                void chooseFile(file);
              }}
            />
            {activeMessages.some((message) => selectedNonces.includes(message.nonce) && canSelect(message)) ? (
              <div className="selection-bar">
                <button type="button" className="text" onClick={clearSelection}>Cancel</button>
                <strong>{activeMessages.filter((message) => selectedNonces.includes(message.nonce) && canSelect(message)).length} selected</strong>
                {shareError && <p className="error">{shareError}</p>}
                <button
                  type="button"
                  className="text"
                  disabled={sharing || forwarding}
                  onClick={() => void shareMessages(activeMessages.filter((message) => selectedNonces.includes(message.nonce)))}
                >
                  {sharing ? "Sharing…" : "Share"}
                </button>
                <button
                  type="button"
                  className="primary send"
                  disabled={sharing || forwarding}
                  onClick={() => beginForward(activeMessages.filter((message) => selectedNonces.includes(message.nonce)))}
                >
                  Forward
                </button>
              </div>
            ) : (
            <form
              className="composer"
              onSubmit={(event) => {
                event.preventDefault();
                void submitMessage();
              }}
            >
              {editing && (
                <div className="reply-chip">
                  <span>
                    <strong>Editing</strong>
                    <em>{previewText(editing) || "Message"}</em>
                  </span>
                  <button type="button" className="text" onClick={cancelEdit}>
                    Cancel
                  </button>
                </div>
              )}
              {replyTo && (
                <div className="reply-chip">
                  <span>
                    <strong>{quoteLabel(replyTo, user.id)}</strong>
                    <em>{replyTo.preview}</em>
                  </span>
                  <button type="button" className="text" onClick={() => active && rememberReply(active.id, null)}>
                    Cancel
                  </button>
                </div>
              )}
              {recording && (
                <div className="recording-bar">
                  <span className="rec-dot" aria-hidden="true" />
                  <strong>{formatDuration(recordMs)}</strong>
                  <span>Recording</span>
                  <button type="button" className="text" onClick={cancelRecording}>
                    Cancel
                  </button>
                </div>
              )}
              {pendingFile && (
                <div className="pending-file">
                  {pendingVoice != null && pendingPreview ? (
                    <audio src={pendingPreview} controls preload="metadata" />
                  ) : (
                    pendingPreview && <img src={pendingPreview} alt="" />
                  )}
                  <span>
                    {pendingVoice != null ? (
                      <strong>Voice message</strong>
                    ) : (
                      !pendingPreview && <strong>{safeFileName(pendingFile.name)}</strong>
                    )}
                    <small>{pendingVoice != null ? formatDuration(pendingVoice) : formatBytes(pendingFile.size)}</small>
                  </span>
                  <button type="button" className="text" onClick={() => chooseFile(null)}>
                    Remove
                  </button>
                </div>
              )}
              {forwardNote && <p className="forward-note">{forwardNote}</p>}
              {sendError && <p className="error inset">{sendError}</p>}
              <div className="composer-row">
                <button type="button" className="icon-button attach" aria-label="Attach a file" disabled={recording || Boolean(editing)} onClick={() => fileInputRef.current?.click()}>
                  <Paperclip />
                </button>
                <button
                  type="button"
                  className={recording ? "icon-button attach live" : "icon-button attach"}
                  aria-label={recording ? "Stop recording" : "Record a voice message"}
                  disabled={sending || Boolean(pendingFile) || Boolean(editing)}
                  onClick={() => (recording ? stopRecording() : void startRecording())}
                >
                  {recording ? <StopGlyph /> : <MicGlyph />}
                </button>
                <textarea
                  ref={textareaRef}
                  rows={1}
                  value={draft}
                  placeholder={recording ? "Recording a voice message" : editing ? (editing.file ? "Edit caption" : "Edit message") : pendingFile ? "Add a caption" : replyTo ? "Reply" : "Message"}
                  onChange={(event) => updateDraft(event.target.value)}
                  onKeyDown={onComposerKey}
                  onPaste={onComposerPaste}
                  maxLength={4000}
                />
                <button
                  className="primary send"
                  type="submit"
                  disabled={sending || recording || (editing ? !draft.trim() && !editing.file : !draft.trim() && !pendingFile)}
                  aria-label={editing ? "Save edit" : "Send message"}
                >
                  {sending ? (editing ? "Saving…" : "Sending…") : editing ? "Save" : "Send"}
                </button>
              </div>
            </form>
            )}
          </>
        ) : (
          <div className="welcome">
            <div className="mark" aria-hidden="true">
              <LockGlyph />
            </div>
            <h2>Your chats live here</h2>
            <p>Pick a conversation, or start a new one with someone's username.</p>
          </div>
        )}
      </section>
      {!active && <div className="word-search">
        {wordLookup && (
          <div className="word-hits">
            {searching && <p className="empty-list">Searching messages…</p>}
            {hits.map((hit) => {
              const conversation = conversations.find((item) => item.id === hit.conversationId);
              if (!conversation) return null;
              return (
                <button type="button" key={`${hit.conversationId}:${hit.nonce}`} className="chat-row search-hit" onClick={() => void openHit(hit)}>
                  <Avatar name={chatTitle(conversation)} username={conversation.kind === "group" ? conversation.id : conversation.peer?.username || chatTitle(conversation)} />
                  <span className="chat-copy">
                    <strong>{chatTitle(conversation)}</strong>
                    <em>{hit.snippet}</em>
                  </span>
                </button>
              );
            })}
            {!searching && hits.length === 0 && <p className="empty-list">No messages match that search.</p>}
          </div>
        )}
        <label className="search-line">
          <span className="sr">Search all chats</span>
          <input value={wordQuery} onChange={(event) => setWordQuery(event.target.value)} placeholder="Search all chats" aria-label="Search all chats" />
          <button type="button" className={wordPhrase ? "phrase on" : "phrase"} aria-pressed={wordPhrase} onClick={() => setWordPhrase((current) => !current)}>
            Search
          </button>
        </label>
      </div>}
      {dialog && (
        <div className="dialog-backdrop" onMouseDown={() => setDialog(null)}>
          <div className="dialog" role="dialog" aria-modal="true" onMouseDown={(event) => event.stopPropagation()}>
            {dialog === "new" && (
              <form onSubmit={(event) => void startChat(event)}>
                <h2>New chat</h2>
                <label className="field">
                  Username
                  <input value={lookup} onChange={(event) => setLookup(event.target.value)} placeholder="bob" autoFocus />
                </label>
                {lookupError && <p className="error">{lookupError}</p>}
                <button className="primary" type="submit">Start chat</button>
                <button
                  className="text"
                  type="button"
                  onClick={() => {
                    setGroupTitle("");
                    setGroupMembers([]);
                    setGroupUser("");
                    setGroupError("");
                    setDialog("group");
                  }}
                >
                  New group
                </button>
              </form>
            )}
            {dialog === "forward" && forwardSources.length > 0 && (
              <form onSubmit={(event) => void forwardToUsername(event)}>
                <h2>{forwardSources.length > 1 ? `Forward ${forwardSources.length} messages` : "Forward message"}</h2>
                <p className="hint">
                  {forwardSources.slice(0, 3).map((message) => previewText(message)).join(", ")}
                  {forwardSources.length > 3 ? ` and ${forwardSources.length - 3} more` : ""}
                </p>
                <label className="field">
                  Send to
                  <input
                    value={forwardLookup}
                    onChange={(event) => setForwardLookup(event.target.value)}
                    placeholder="Search chats or a username"
                    autoFocus
                  />
                </label>
                <div className="forward-list">
                  {conversations
                    .filter((conversation) => matchesChat(conversation, forwardLookup))
                    .map((conversation) => {
                      const title = chatTitle(conversation);
                      const group = conversation.kind === "group";
                      return (
                      <button
                        type="button"
                        key={conversation.id}
                        className="chat-row"
                        disabled={forwarding}
                        onClick={() => void deliverForward(conversation)}
                      >
                        <Avatar name={title} username={group ? conversation.id : conversation.peer?.username || title} />
                        <span className="chat-copy">
                          <strong>{title}</strong>
                          <small>{group ? `${conversation.members.length + 1} people` : `@${conversation.peer?.username ?? ""}`}</small>
                        </span>
                      </button>
                      );
                    })}
                </div>
                {forwardError && <p className="error">{forwardError}</p>}
                <button className="primary" type="submit" disabled={forwarding || !forwardLookup.trim()}>
                  {forwarding ? "Forwarding…" : "Forward to username"}
                </button>
              </form>
            )}
            {dialog === "delete" && deleteTarget && (
              <div>
                <h2>Delete message</h2>
                <p className="hint">
                  {conversations.find((item) => item.id === deleteTarget.conversationId)?.kind === "group"
                    ? `This removes “${previewText(deleteTarget) || "this message"}” for everyone in the group.`
                    : `This removes “${previewText(deleteTarget) || "this message"}” for both of you.`}
                </p>
                {deleteError && <p className="error">{deleteError}</p>}
                <button className="primary" type="button" disabled={deleting} onClick={() => void confirmDelete()}>
                  {deleting ? "Deleting…" : "Delete"}
                </button>
              </div>
            )}
            {dialog === "group" && (
              <form onSubmit={(event) => void startGroup(event)}>
                <h2>New group</h2>
                <p className="hint">Add at least two other people. You start the group as its admin and can add or remove people later. Each message is encrypted separately for everyone in the group. People who join later only see messages sent after they join.</p>
                <label className="field">
                  Group name
                  <input value={groupTitle} onChange={(event) => setGroupTitle(event.target.value)} placeholder="Weekend plans" maxLength={40} autoFocus />
                </label>
                <div className="member-picks">
                  {groupMembers.map((username) => (
                    <button
                      type="button"
                      key={username}
                      className="member-chip"
                      onClick={() => setGroupMembers((current) => current.filter((item) => item !== username))}
                    >
                      @{username} ×
                    </button>
                  ))}
                </div>
                <label className="field">
                  Add a username
                  <input value={groupUser} onChange={(event) => setGroupUser(event.target.value)} placeholder="bob" onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      addPlannedMember(event);
                    }
                  }} />
                </label>
                <button className="text" type="button" onClick={(event) => addPlannedMember(event)}>Add person</button>
                {groupError && <p className="error">{groupError}</p>}
                <button className="primary" type="submit" disabled={groupBusy || !groupTitle.trim() || groupMembers.length < 2}>
                  {groupBusy ? "Creating…" : "Create group"}
                </button>
              </form>
            )}
            {dialog === "people" && active?.kind === "group" && (
              <div>
                <h2>{chatTitle(active)}</h2>
                <p className="hint">
                  {active.members.length + 1} people. The admin can add and remove people.
                  {active.viewerRole === "admin" ? " New members don't receive older messages. If you leave, someone else becomes the admin." : ""}
                </p>
                <ul className="people-list">
                  <li>
                    <span>
                      <strong>{user.displayName}</strong>
                      <small>@{user.username} · you{active.viewerRole === "admin" ? " · admin" : ""}</small>
                    </span>
                  </li>
                  {active.members.map((member) => (
                    <li key={member.id}>
                      <span>
                        <strong>{member.displayName}</strong>
                        <small>@{member.username}{member.role === "admin" ? " · admin" : ""}</small>
                      </span>
                      {active.viewerRole === "admin" && member.role !== "admin" && (
                        <button type="button" className="text danger" disabled={groupBusy} onClick={() => void removeMember(member.id)}>
                          Remove
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
                {active.viewerRole === "admin" && (
                  <form onSubmit={(event) => void inviteMember(event)}>
                    <label className="field">
                      Add a username
                      <input value={groupUser} onChange={(event) => setGroupUser(event.target.value)} placeholder="carol" />
                    </label>
                    {groupError && <p className="error">{groupError}</p>}
                    <button className="primary" type="submit" disabled={groupBusy || !groupUser.trim()}>
                      {groupBusy ? "Adding…" : "Add person"}
                    </button>
                  </form>
                )}
                {active.viewerRole !== "admin" && groupError && <p className="error">{groupError}</p>}
                <button className="text danger" type="button" disabled={groupBusy} onClick={() => void leaveCurrentGroup()}>
                  Leave group
                </button>
              </div>
            )}
            {dialog === "safety" && active?.peer && (
              <div>
                <h2>Safety number</h2>
                <p className="hint">Compare these digits with {active.peer.displayName} on a call or in person. If they match, you share the same encryption keys.</p>
                <div className="safety-grid">{safety.map((group, index) => <span key={`${group}-${index}`}>{group}</span>)}</div>
                <button
                  type="button"
                  className="text"
                  onClick={() => void navigator.clipboard.writeText(safety.join(" "))}
                >
                  Copy number
                </button>
              </div>
            )}
            {dialog === "profile" && (
              <div>
                <h2>{user.displayName}</h2>
                <p className="hint">@{user.username} · {user.provider === "google" ? "Gmail sign-in" : "Password sign-in"}</p>
                <button type="button" className="text" onClick={() => setShowFingerprint((current) => !current)}>
                  {showFingerprint ? "Hide key fingerprint" : "Show key fingerprint"}
                </button>
                {showFingerprint && (
                  <>
                    <div className="safety-grid">{fingerprint.map((group, index) => <span key={`${group}-${index}`}>{group}</span>)}</div>
                    <button type="button" className="text" onClick={() => setDialog("reset")}>Reset encryption keys</button>
                  </>
                )}
                <div className="row-actions">
                  {user.provider === "password" && (
                    <button
                      type="button"
                      className="text"
                      onClick={() => {
                        setPasswordCurrent("");
                        setPasswordNext("");
                        setPasswordConfirm("");
                        setPasswordError("");
                        setDialog("password");
                      }}
                    >
                      Change password
                    </button>
                  )}
                  <button type="button" className="text" onClick={onLogout}>Sign out</button>
                </div>
              </div>
            )}
            {dialog === "password" && (
              <form onSubmit={(event) => void changePassword(event)}>
                <h2>Change password</h2>
                <p className="hint">Your chats stay readable. The new password unlocks the same encryption keys.</p>
                <label className="field">
                  Current password
                  <input type="password" value={passwordCurrent} onChange={(event) => setPasswordCurrent(event.target.value)} autoFocus />
                </label>
                <label className="field">
                  New password
                  <input type="password" value={passwordNext} onChange={(event) => setPasswordNext(event.target.value)} />
                </label>
                <label className="field">
                  Confirm new password
                  <input type="password" value={passwordConfirm} onChange={(event) => setPasswordConfirm(event.target.value)} />
                </label>
                {passwordError && <p className="error">{passwordError}</p>}
                <button className="primary" type="submit" disabled={passwordBusy}>{passwordBusy ? "Saving…" : "Save password"}</button>
              </form>
            )}
            {dialog === "reset" && (
              <form onSubmit={(event) => void replaceKeys(event)}>
                <h2>Reset encryption keys</h2>
                <p className="hint">
                  {user.provider === "password"
                    ? "Enter your account password. It wraps the new keys. Older messages stay unreadable."
                    : "Choose a new passphrase. It stays in this browser. Older messages stay unreadable."}
                </p>
                <label className="field">
                  {user.provider === "password" ? "Password" : "New passphrase"}
                  <input type="password" value={resetSecret} onChange={(event) => setResetSecret(event.target.value)} autoFocus />
                </label>
                {user.provider === "google" && (
                  <label className="field">
                    Confirm passphrase
                    <input type="password" value={resetConfirm} onChange={(event) => setResetConfirm(event.target.value)} />
                  </label>
                )}
                <label className="check">
                  <input type="checkbox" checked={resetUnderstood} onChange={(event) => setResetUnderstood(event.target.checked)} />
                  I understand older messages will be unreadable.
                </label>
                {resetError && <p className="error">{resetError}</p>}
                <button className="primary" type="submit" disabled={resetBusy}>{resetBusy ? "Replacing…" : "Replace keys"}</button>
              </form>
            )}
          </div>
        </div>
      )}
      {photoFile && (
        <PhotoEditor
          file={photoFile}
          onCancel={() => setPhotoFile(null)}
          onUse={(next) => {
            setPhotoFile(null);
            attachReady(next);
          }}
        />
      )}
    </main>
  );
}

function Avatar({ name, username, online }: { name: string; username: string; online?: boolean }) {
  return (
    <span className="avatar-wrap">
      <span className="avatar" style={{ background: `hsl(${hue(username)} 42% 32%)` }}>{initials(name)}</span>
      {online && <span className="presence" />}
    </span>
  );
}

function VoiceNote({ conversationId, file, localUrl }: { conversationId: string; file: AttachmentMeta; localUrl?: string }) {
  const [url, setUrl] = useState<string | null>(localUrl ?? null);
  const [error, setError] = useState("");
  const owned = useRef<string | null>(null);

  useEffect(() => {
    if (localUrl) return;
    let cancelled = false;
    decryptAttachment(conversationId, file)
      .then((bytes) => {
        if (cancelled) return;
        const copy = new Uint8Array(bytes.byteLength);
        copy.set(bytes);
        const next = URL.createObjectURL(new Blob([copy.buffer], { type: playbackType(file.type) }));
        owned.current = next;
        setUrl(next);
      })
      .catch(() => {
        if (!cancelled) setError("Couldn't open this voice message.");
      });
    return () => {
      cancelled = true;
      if (owned.current) URL.revokeObjectURL(owned.current);
    };
  }, [conversationId, file, localUrl]);

  return (
    <div className="voice-note">
      {url ? (
        <audio controls preload="metadata" src={url} />
      ) : (
        <p>{error || "Opening voice message…"}</p>
      )}
      {file.durationMs != null && <small>{formatDuration(file.durationMs)}</small>}
    </div>
  );
}

function playbackType(type: string) {
  if (type.includes("mp4")) return "audio/mp4";
  if (type.includes("ogg")) return "audio/ogg";
  return "audio/webm";
}

function MicGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="icon" aria-hidden="true">
      <rect x="9" y="3" width="6" height="11" rx="3" fill="none" stroke="currentColor" strokeWidth="1.8" />
      <path d="M6 11a6 6 0 0 0 12 0M12 17v3" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

function StopGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="icon" aria-hidden="true">
      <rect x="7" y="7" width="10" height="10" rx="2" fill="currentColor" />
    </svg>
  );
}

function FolderFace({ conversationId, replies }: { conversationId: string; replies: ChatMessage[] }) {
  const images = replies.filter((reply) => reply.file && isPreviewableImage(reply.file.type)).slice(0, 3);
  const notes = replies.filter((reply) => !reply.file || !isPreviewableImage(reply.file.type)).slice(0, 2);
  return (
    <span className="folder-face">
      <FolderGlyph />
      <span className="folder-pocket">
        {images.map((reply) =>
          reply.file ? <FolderThumb key={reply.nonce} conversationId={conversationId} file={reply.file} localUrl={reply.localUrl} /> : null,
        )}
        {notes.map((reply) => (
          <em key={reply.nonce}>{previewText(reply).slice(0, 42)}</em>
        ))}
        {replies.length === 0 && <em>Empty</em>}
      </span>
    </span>
  );
}

function FolderThumb({ conversationId, file, localUrl }: { conversationId: string; file: AttachmentMeta; localUrl?: string }) {
  const [url, setUrl] = useState<string | null>(localUrl ?? null);
  const owned = useRef<string | null>(null);

  useEffect(() => {
    if (localUrl) return;
    let cancelled = false;
    decryptAttachment(conversationId, file)
      .then((bytes) => {
        if (cancelled) return;
        const copy = new Uint8Array(bytes.byteLength);
        copy.set(bytes);
        const next = URL.createObjectURL(new Blob([copy.buffer], { type: file.type }));
        owned.current = next;
        setUrl(next);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
      if (owned.current) URL.revokeObjectURL(owned.current);
    };
  }, [conversationId, file, localUrl]);

  if (!url) return null;
  return <img src={url} alt="" />;
}

function FolderGlyph() {
  return (
    <svg viewBox="0 0 92 68" className="icon folder-svg" aria-hidden="true">
      <path d="M4 18a6 6 0 0 1 6-6h24l8 8h40a6 6 0 0 1 6 6v32a6 6 0 0 1-6 6H10a6 6 0 0 1-6-6V18z" fill="currentColor" />
    </svg>
  );
}

function DotsGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="dots-icon" aria-hidden="true">
      <circle cx="12" cy="5" r="1.7" />
      <circle cx="12" cy="12" r="1.7" />
      <circle cx="12" cy="19" r="1.7" />
    </svg>
  );
}

function Paperclip() {
  return (
    <svg viewBox="0 0 24 24" className="icon" aria-hidden="true">
      <path
        d="M8 12.5 14.8 5.7a3.2 3.2 0 0 1 4.5 4.5l-8.2 8.2a4.6 4.6 0 0 1-6.5-6.5l7.4-7.4"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}

function AttachmentCard({ conversationId, file, localUrl }: { conversationId: string; file: AttachmentMeta; localUrl?: string }) {
  if (file.voice) return <VoiceNote conversationId={conversationId} file={file} localUrl={localUrl} />;
  return <FileAttachment conversationId={conversationId} file={file} localUrl={localUrl} />;
}

function FileAttachment({ conversationId, file, localUrl }: { conversationId: string; file: AttachmentMeta; localUrl?: string }) {
  const [url, setUrl] = useState<string | null>(localUrl ?? null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const owned = useRef<string | null>(null);
  const image = isPreviewableImage(file.type);

  useEffect(() => {
    if (localUrl || !image) return;
    let cancelled = false;
    decryptAttachment(conversationId, file)
      .then((bytes) => {
        if (cancelled) return;
        const copy = new Uint8Array(bytes.byteLength);
        copy.set(bytes);
        const next = URL.createObjectURL(new Blob([copy.buffer], { type: file.type }));
        owned.current = next;
        setUrl(next);
      })
      .catch(() => {
        if (!cancelled) setError("Couldn't open this file.");
      });
    return () => {
      cancelled = true;
      if (owned.current) URL.revokeObjectURL(owned.current);
    };
  }, [conversationId, file, image, localUrl]);

  async function download() {
    setBusy(true);
    setError("");
    try {
      let href = localUrl ?? null;
      let revoke = false;
      if (!href) {
        const bytes = await decryptAttachment(conversationId, file);
        const copy = new Uint8Array(bytes.byteLength);
        copy.set(bytes);
        href = URL.createObjectURL(new Blob([copy.buffer], { type: file.type || "application/octet-stream" }));
        revoke = true;
      }
      const link = document.createElement("a");
      link.href = href;
      link.download = file.name;
      link.click();
      if (revoke) URL.revokeObjectURL(href);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Couldn't download this file.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={image ? "attachment image" : "attachment"}>
      {image && url && <img src={url} alt="Photo" />}
      <div className="file-card">
        <span>
          {!image && <strong>{file.name}</strong>}
          <small>{formatBytes(file.size)}</small>
        </span>
        <button type="button" className="text file-download" onClick={() => void download()} disabled={busy}>
          {busy ? "Opening…" : "Download"}
        </button>
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

function PeopleGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="icon" aria-hidden="true">
      <circle cx="9" cy="8" r="2.4" fill="none" stroke="currentColor" strokeWidth="1.8" />
      <circle cx="16" cy="9" r="2" fill="none" stroke="currentColor" strokeWidth="1.8" />
      <path d="M4.5 18c.6-2.4 2.4-3.6 4.5-3.6s3.9 1.2 4.5 3.6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      <path d="M13.5 14.6c1.4-.3 2.8.1 3.8 1.2 1 .9 1.5 2.2 1.7 3.2" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

function LockGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="icon" aria-hidden="true">
      <rect x="5" y="11" width="14" height="10" rx="2" fill="none" stroke="currentColor" strokeWidth="1.8" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" fill="none" stroke="currentColor" strokeWidth="1.8" />
    </svg>
  );
}
