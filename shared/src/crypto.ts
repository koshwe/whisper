export const PROTOCOL = "whisper-v1";
export const AUTH_ITERATIONS = 200_000;
export const WRAP_ITERATIONS = 200_000;
export const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MESSAGE_LIMIT = 4000;

export type AttachmentMeta = {
  id: string;
  name: string;
  type: string;
  size: number;
  key: string;
  iv: string;
  sha256: string;
  voice?: boolean;
  durationMs?: number;
};

export type QuotedMessage = {
  id: string;
  senderId: string;
  sender: string;
  preview: string;
};

export type ChatPayload = {
  text: string;
  file: AttachmentMeta | null;
  reply: QuotedMessage | null;
  forwarded: boolean;
};

export type CipherBundle = {
  ephPublic: string;
  iv: string;
  ciphertext: string;
};

export type MessageEnvelope = {
  nonce: string;
  forRecipient: CipherBundle;
  forSender: CipherBundle;
  signature: string;
};

export type GroupCopy = {
  userId: string;
  ephPublic: string;
  iv: string;
  ciphertext: string;
  signature: string;
};

export type GroupEnvelope = {
  nonce: string;
  copies: GroupCopy[];
};

export type Identity = {
  ecdhPublic: string;
  ecdsaPublic: string;
  ecdhPrivate: CryptoKey;
  ecdsaPrivate: CryptoKey;
};

export type WrappedIdentity = {
  ecdhPublic: string;
  ecdsaPublic: string;
  wrappedEcdh: string;
  wrappedEcdsa: string;
  wrapSalt: string;
  wrapIterations: number;
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function webCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(
      "This browser turns encryption off on a plain http address. Open the https:// address for this computer, then continue past the certificate warning.",
    );
  }
  return subtle;
}

function encode(value: string): Uint8Array {
  return textEncoder.encode(value);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left, 0);
  combined.set(right, left.length);
  return combined;
}

async function exportSpki(key: CryptoKey): Promise<string> {
  const exported = await webCrypto().exportKey("spki", key);
  return bytesToBase64(new Uint8Array(exported));
}

async function exportPkcs8(key: CryptoKey): Promise<string> {
  const exported = await webCrypto().exportKey("pkcs8", key);
  return bytesToBase64(new Uint8Array(exported));
}

async function importEcdhPublic(spki: string): Promise<CryptoKey> {
  return webCrypto().importKey("spki", toArrayBuffer(base64ToBytes(spki)), { name: "ECDH", namedCurve: "P-256" }, true, []);
}

async function importEcdhPrivate(pkcs8: string): Promise<CryptoKey> {
  return webCrypto().importKey(
    "pkcs8",
    toArrayBuffer(base64ToBytes(pkcs8)),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
}

async function importEcdsaPublic(spki: string): Promise<CryptoKey> {
  return webCrypto().importKey(
    "spki",
    toArrayBuffer(base64ToBytes(spki)),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
}

async function importEcdsaPrivate(pkcs8: string): Promise<CryptoKey> {
  return webCrypto().importKey(
    "pkcs8",
    toArrayBuffer(base64ToBytes(pkcs8)),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
}

export async function generateIdentity(): Promise<Identity> {
  const ecdh = await webCrypto().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const ecdsa = await webCrypto().generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return {
    ecdhPublic: await exportSpki(ecdh.publicKey),
    ecdsaPublic: await exportSpki(ecdsa.publicKey),
    ecdhPrivate: ecdh.privateKey,
    ecdsaPrivate: ecdsa.privateKey,
  };
}

async function deriveWrapKey(password: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const material = await webCrypto().importKey("raw", toArrayBuffer(encode(password)), "PBKDF2", false, ["deriveKey"]);
  return webCrypto().deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: toArrayBuffer(salt), iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// Login verifier and key-wrapping key use different salts.
// The raw password never goes to the server, so a database copy cannot unwrap private keys.
export async function deriveAuthVerifier(username: string, password: string): Promise<string> {
  const salt = encode(`whisper-auth-v1:${username.trim().toLowerCase()}`);
  const material = await webCrypto().importKey("raw", toArrayBuffer(encode(password)), "PBKDF2", false, ["deriveBits"]);
  const bits = await webCrypto().deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: toArrayBuffer(salt), iterations: AUTH_ITERATIONS },
    material,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

async function encryptPacked(value: string, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await webCrypto().encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(encode(value)));
  return `${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(ciphertext))}`;
}

async function decryptPacked(packed: string, key: CryptoKey): Promise<string> {
  const dot = packed.indexOf(".");
  if (dot <= 0) throw new Error("Wrapped key is invalid.");
  const iv = base64ToBytes(packed.slice(0, dot));
  const ciphertext = base64ToBytes(packed.slice(dot + 1));
  const plaintext = await webCrypto().decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(ciphertext),
  );
  return textDecoder.decode(plaintext);
}

export async function wrapIdentity(identity: Identity, password: string): Promise<WrappedIdentity> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveWrapKey(password, salt, WRAP_ITERATIONS);
  return {
    ecdhPublic: identity.ecdhPublic,
    ecdsaPublic: identity.ecdsaPublic,
    wrappedEcdh: await encryptPacked(await exportPkcs8(identity.ecdhPrivate), key),
    wrappedEcdsa: await encryptPacked(await exportPkcs8(identity.ecdsaPrivate), key),
    wrapSalt: bytesToBase64(salt),
    wrapIterations: WRAP_ITERATIONS,
  };
}

export async function unwrapIdentity(wrapped: WrappedIdentity, password: string): Promise<Identity> {
  const key = await deriveWrapKey(password, base64ToBytes(wrapped.wrapSalt), wrapped.wrapIterations);
  return {
    ecdhPublic: wrapped.ecdhPublic,
    ecdsaPublic: wrapped.ecdsaPublic,
    ecdhPrivate: await importEcdhPrivate(await decryptPacked(wrapped.wrappedEcdh, key)),
    ecdsaPrivate: await importEcdsaPrivate(await decryptPacked(wrapped.wrappedEcdsa, key)),
  };
}

function additionalData(input: {
  conversationId: string;
  senderId: string;
  nonce: string;
  copy: "recipient" | "sender";
}): Uint8Array {
  return encode([PROTOCOL, input.conversationId, input.senderId, input.nonce, input.copy].join("\n"));
}

export function signaturePayload(input: {
  conversationId: string;
  senderId: string;
  nonce: string;
  forRecipient: CipherBundle;
  forSender: CipherBundle;
}): Uint8Array {
  return encode(
    JSON.stringify([
      PROTOCOL,
      input.conversationId,
      input.senderId,
      input.nonce,
      input.forRecipient.ephPublic,
      input.forRecipient.iv,
      input.forRecipient.ciphertext,
      input.forSender.ephPublic,
      input.forSender.iv,
      input.forSender.ciphertext,
    ]),
  );
}

async function messageKey(sharedBits: ArrayBuffer, iv: Uint8Array): Promise<CryptoKey> {
  const baseKey = await webCrypto().importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return webCrypto().deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(encode("whisper-hkdf-v1")),
      info: toArrayBuffer(concat(encode("whisper-msg-v1"), iv)),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function seal(plaintext: string, recipientPublic: string, aad: Uint8Array): Promise<CipherBundle> {
  const ephemeral = await webCrypto().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const recipient = await importEcdhPublic(recipientPublic);
  const shared = await webCrypto().deriveBits({ name: "ECDH", public: recipient }, ephemeral.privateKey, 256);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aes = await messageKey(shared, iv);
  const ciphertext = await webCrypto().encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad) },
    aes,
    toArrayBuffer(encode(plaintext)),
  );
  return {
    ephPublic: await exportSpki(ephemeral.publicKey),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

export async function encryptMessage(input: {
  identity: Identity;
  recipientEcdhPublic: string;
  conversationId: string;
  senderId: string;
  plaintext: string;
  nonce?: string;
}): Promise<MessageEnvelope> {
  const plaintext = input.plaintext;
  if (!plaintext.trim()) throw new Error("Message is empty.");
  if (plaintext.length > MESSAGE_LIMIT) throw new Error("Message is too long.");
  const nonce = input.nonce?.trim() || bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
  const forRecipient = await seal(
    plaintext,
    input.recipientEcdhPublic,
    additionalData({ conversationId: input.conversationId, senderId: input.senderId, nonce, copy: "recipient" }),
  );
  const forSender = await seal(
    plaintext,
    input.identity.ecdhPublic,
    additionalData({ conversationId: input.conversationId, senderId: input.senderId, nonce, copy: "sender" }),
  );
  const payload = signaturePayload({
    conversationId: input.conversationId,
    senderId: input.senderId,
    nonce,
    forRecipient,
    forSender,
  });
  const signature = await webCrypto().sign({ name: "ECDSA", hash: "SHA-256" }, input.identity.ecdsaPrivate, toArrayBuffer(payload));
  return {
    nonce,
    forRecipient,
    forSender,
    signature: bytesToBase64(new Uint8Array(signature)),
  };
}

export async function verifyEnvelope(input: {
  envelope: MessageEnvelope;
  conversationId: string;
  senderId: string;
  senderEcdsaPublic: string;
}): Promise<boolean> {
  try {
    const payload = signaturePayload({
      conversationId: input.conversationId,
      senderId: input.senderId,
      nonce: input.envelope.nonce,
      forRecipient: input.envelope.forRecipient,
      forSender: input.envelope.forSender,
    });
    const publicKey = await importEcdsaPublic(input.senderEcdsaPublic);
    return webCrypto().verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      toArrayBuffer(base64ToBytes(input.envelope.signature)),
      toArrayBuffer(payload),
    );
  } catch {
    return false;
  }
}

export async function decryptMessage(input: {
  envelope: MessageEnvelope;
  conversationId: string;
  senderId: string;
  senderEcdsaPublic: string;
  myEcdhPrivate: CryptoKey;
  copy: "recipient" | "sender";
}): Promise<string> {
  const valid = await verifyEnvelope({
    envelope: input.envelope,
    conversationId: input.conversationId,
    senderId: input.senderId,
    senderEcdsaPublic: input.senderEcdsaPublic,
  });
  if (!valid) throw new Error("Message signature is invalid.");
  const bundle = input.copy === "recipient" ? input.envelope.forRecipient : input.envelope.forSender;
  const ephemeral = await importEcdhPublic(bundle.ephPublic);
  const shared = await webCrypto().deriveBits({ name: "ECDH", public: ephemeral }, input.myEcdhPrivate, 256);
  const iv = base64ToBytes(bundle.iv);
  const aes = await messageKey(shared, iv);
  const plaintext = await webCrypto().decrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(
        additionalData({
          conversationId: input.conversationId,
          senderId: input.senderId,
          nonce: input.envelope.nonce,
          copy: input.copy,
        }),
      ),
    },
    aes,
    toArrayBuffer(base64ToBytes(bundle.ciphertext)),
  );
  return textDecoder.decode(plaintext);
}

function groupAdditionalData(input: { conversationId: string; senderId: string; nonce: string; memberId: string }) {
  return encode([PROTOCOL, "group", input.conversationId, input.senderId, input.nonce, input.memberId].join("\n"));
}

function groupSignaturePayload(input: {
  conversationId: string;
  senderId: string;
  nonce: string;
  memberId: string;
  bundle: CipherBundle;
}) {
  return encode(
    JSON.stringify([
      PROTOCOL,
      "group",
      input.conversationId,
      input.senderId,
      input.nonce,
      input.memberId,
      input.bundle.ephPublic,
      input.bundle.iv,
      input.bundle.ciphertext,
    ]),
  );
}

export async function encryptGroupMessage(input: {
  identity: Identity;
  members: Array<{ userId: string; ecdhPublic: string }>;
  conversationId: string;
  senderId: string;
  plaintext: string;
  nonce?: string;
}): Promise<GroupEnvelope> {
  const plaintext = input.plaintext;
  if (!plaintext.trim()) throw new Error("Message is empty.");
  if (plaintext.length > MESSAGE_LIMIT) throw new Error("Message is too long.");
  if (input.members.length < 1 || input.members.length > 16) throw new Error("A group can have up to 16 people.");
  const nonce = input.nonce?.trim() || bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
  const copies: GroupCopy[] = [];
  for (const member of input.members) {
    const bundle = await seal(plaintext, member.ecdhPublic, groupAdditionalData({
      conversationId: input.conversationId,
      senderId: input.senderId,
      nonce,
      memberId: member.userId,
    }));
    const payload = groupSignaturePayload({
      conversationId: input.conversationId,
      senderId: input.senderId,
      nonce,
      memberId: member.userId,
      bundle,
    });
    const signature = await webCrypto().sign({ name: "ECDSA", hash: "SHA-256" }, input.identity.ecdsaPrivate, toArrayBuffer(payload));
    copies.push({
      userId: member.userId,
      ephPublic: bundle.ephPublic,
      iv: bundle.iv,
      ciphertext: bundle.ciphertext,
      signature: bytesToBase64(new Uint8Array(signature)),
    });
  }
  return { nonce, copies };
}

export async function verifyGroupCopy(input: {
  conversationId: string;
  senderId: string;
  nonce: string;
  memberId: string;
  bundle: CipherBundle;
  signature: string;
  senderEcdsaPublic: string;
}) {
  try {
    const payload = groupSignaturePayload({
      conversationId: input.conversationId,
      senderId: input.senderId,
      nonce: input.nonce,
      memberId: input.memberId,
      bundle: input.bundle,
    });
    const publicKey = await importEcdsaPublic(input.senderEcdsaPublic);
    return webCrypto().verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      toArrayBuffer(base64ToBytes(input.signature)),
      toArrayBuffer(payload),
    );
  } catch {
    return false;
  }
}

export async function decryptGroupMessage(input: {
  conversationId: string;
  senderId: string;
  nonce: string;
  memberId: string;
  bundle: CipherBundle;
  signature: string;
  senderEcdsaPublic: string;
  myEcdhPrivate: CryptoKey;
}) {
  const valid = await verifyGroupCopy(input);
  if (!valid) throw new Error("Message signature is invalid.");
  const ephemeral = await importEcdhPublic(input.bundle.ephPublic);
  const shared = await webCrypto().deriveBits({ name: "ECDH", public: ephemeral }, input.myEcdhPrivate, 256);
  const iv = base64ToBytes(input.bundle.iv);
  const aes = await messageKey(shared, iv);
  const plaintext = await webCrypto().decrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(groupAdditionalData({
        conversationId: input.conversationId,
        senderId: input.senderId,
        nonce: input.nonce,
        memberId: input.memberId,
      })),
    },
    aes,
    toArrayBuffer(base64ToBytes(input.bundle.ciphertext)),
  );
  return textDecoder.decode(plaintext);
}

function cleanQuote(value: unknown): QuotedMessage | null {
  if (!value || typeof value !== "object") return null;
  const quote = value as Record<string, unknown>;
  if (
    typeof quote.id !== "string" ||
    typeof quote.senderId !== "string" ||
    typeof quote.sender !== "string" ||
    typeof quote.preview !== "string"
  ) {
    return null;
  }
  const id = quote.id.trim().slice(0, 80);
  const senderId = quote.senderId.trim().slice(0, 80);
  const sender = quote.sender.replace(/[\u0000-\u001f]/g, "").trim().slice(0, 80);
  const preview = quote.preview.replace(/[\u0000-\u001f]/g, " ").replace(/\s+/g, " ").trim().slice(0, 160);
  if (!id || !senderId || !sender || !preview) return null;
  return { id, senderId, sender, preview };
}

export function packPayload(payload: {
  text: string;
  file?: AttachmentMeta | null;
  reply?: QuotedMessage | null;
  forwarded?: boolean;
}): string {
  const file = payload.file ?? null;
  const reply = payload.reply ? cleanQuote(payload.reply) : null;
  const forwarded = payload.forwarded === true;
  if (!file && !reply && !forwarded) return payload.text;
  if (file && !reply && !forwarded) return JSON.stringify({ v: 2, text: payload.text, file });
  return JSON.stringify({ v: 3, text: payload.text, file, reply, forwarded: forwarded || undefined });
}

function isAttachment(value: unknown): value is AttachmentMeta {
  if (!value || typeof value !== "object") return false;
  const file = value as AttachmentMeta;
  return (
    typeof file.id === "string" &&
    typeof file.name === "string" &&
    typeof file.type === "string" &&
    typeof file.size === "number" &&
    typeof file.key === "string" &&
    typeof file.iv === "string" &&
    typeof file.sha256 === "string"
  );
}

function readAttachment(value: unknown): AttachmentMeta | null {
  if (!isAttachment(value)) return null;
  const duration = typeof value.durationMs === "number" && Number.isFinite(value.durationMs)
    ? Math.min(10 * 60 * 1000, Math.max(0, Math.round(value.durationMs)))
    : undefined;
  return {
    id: value.id,
    name: value.name,
    type: value.type,
    size: value.size,
    key: value.key,
    iv: value.iv,
    sha256: value.sha256,
    ...(value.voice === true ? { voice: true, ...(duration !== undefined ? { durationMs: duration } : {}) } : {}),
  };
}

function plainPayload(text: string): ChatPayload {
  return { text, file: null, reply: null, forwarded: false };
}

export function unpackPayload(plaintext: string): ChatPayload {
  const version = plaintext.startsWith('{"v":3') ? 3 : plaintext.startsWith('{"v":2') ? 2 : 0;
  if (!version) return plainPayload(plaintext);
  try {
    const parsed = JSON.parse(plaintext) as { v?: number; text?: unknown; file?: unknown; reply?: unknown; forwarded?: unknown };
    if (parsed.v !== version) return plainPayload(plaintext);
    const file = parsed.file == null ? null : readAttachment(parsed.file);
    if (parsed.file != null && !file) return plainPayload(plaintext);
    return {
      text: typeof parsed.text === "string" ? parsed.text : "",
      file,
      reply: version === 3 ? cleanQuote(parsed.reply) : null,
      forwarded: version === 3 && parsed.forwarded === true,
    };
  } catch {
    return plainPayload(plaintext);
  }
}

export async function sha256Base64(bytes: Uint8Array): Promise<string> {
  const digest = await webCrypto().digest("SHA-256", toArrayBuffer(bytes));
  return bytesToBase64(new Uint8Array(digest));
}

export async function encryptFile(bytes: Uint8Array): Promise<{ ciphertext: Uint8Array; key: string; iv: string }> {
  if (bytes.byteLength === 0) throw new Error("That file is empty.");
  if (bytes.byteLength > MAX_FILE_BYTES) throw new Error("Files need to be 8 MB or smaller.");
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aes = await webCrypto().importKey("raw", toArrayBuffer(rawKey), "AES-GCM", false, ["encrypt"]);
  const encrypted = await webCrypto().encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, aes, toArrayBuffer(bytes));
  return { ciphertext: new Uint8Array(encrypted), key: bytesToBase64(rawKey), iv: bytesToBase64(iv) };
}

export async function decryptFile(ciphertext: Uint8Array, key: string, iv: string): Promise<Uint8Array> {
  const aes = await webCrypto().importKey("raw", toArrayBuffer(base64ToBytes(key)), "AES-GCM", false, ["decrypt"]);
  const plaintext = await webCrypto().decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(base64ToBytes(iv)) },
    aes,
    toArrayBuffer(ciphertext),
  );
  return new Uint8Array(plaintext);
}

export async function safetyNumber(publicA: string, publicB: string): Promise<string[]> {
  const [first, second] = [publicA, publicB].sort();
  const digest = await webCrypto().digest("SHA-256", toArrayBuffer(encode(`${first}\n${second}`)));
  const bytes = new Uint8Array(digest);
  const groups: string[] = [];
  for (let index = 0; index < 12; index += 1) {
    const value = ((bytes[index * 2] << 8) | bytes[index * 2 + 1]) % 100000;
    groups.push(value.toString().padStart(5, "0"));
  }
  return groups;
}
