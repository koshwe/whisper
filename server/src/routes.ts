import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import { WRAP_ITERATIONS, verifyEnvelope, verifyGroupCopy, type CipherBundle, type MessageEnvelope } from "@whisper/shared";
import type { AccountUser, UserRow, WhisperDb } from "./db.ts";
import { HttpError } from "./errors.ts";
import {
  beginGoogleLogin,
  clientOrigin,
  consumeExchangeCode,
  consumeGoogleState,
  createExchangeCode,
  exchangeGoogleCode,
  googleEnabled,
} from "./google.ts";
import { isOnline, notifyUsers, sendToUser } from "./hub.ts";

const hits = new Map<string, number[]>();

function rateLimit(key: string, limit: number, windowMs: number) {
  const now = Date.now();
  const recent = (hits.get(key) ?? []).filter((time) => now - time < windowMs);
  if (recent.length >= limit) return false;
  recent.push(now);
  hits.set(key, recent);
  return true;
}

function clientIp(req: Request) {
  return req.socket.remoteAddress ?? "local";
}

function hashVerifier(verifier: string) {
  return createHash("sha256").update(verifier).digest("base64url");
}

function verifierMatches(verifier: string, stored: string) {
  const actual = Buffer.from(hashVerifier(verifier));
  const expected = Buffer.from(stored);
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}

function asyncRoute(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };
}

function requireString(value: unknown, message: string, max = 200) {
  if (typeof value !== "string") throw new HttpError(400, message);
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max) throw new HttpError(400, message);
  return trimmed;
}

function normalizeUsername(value: unknown) {
  const username = requireString(value, "Usernames are 3–20 characters: letters, numbers, and underscores.", 20).toLowerCase();
  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    throw new HttpError(400, "Usernames are 3–20 characters: letters, numbers, and underscores.");
  }
  return username;
}

function normalizeDisplayName(value: unknown, fallback: string) {
  if (value == null || value === "") return fallback;
  if (typeof value !== "string") throw new HttpError(400, "Enter a display name.");
  const name = value.trim().replace(/\s+/g, " ");
  if (!name || name.length > 40 || /[\u0000-\u001f]/.test(name)) {
    throw new HttpError(400, "Display names can be up to 40 characters.");
  }
  return name;
}

function requireBase64(value: unknown, field: string, max: number) {
  if (typeof value !== "string" || value.length === 0 || value.length > max || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new HttpError(400, `Invalid ${field}.`);
  }
  return value;
}

function requireWrapped(value: unknown, field: string) {
  if (typeof value !== "string" || value.length > 4000) throw new HttpError(400, `Invalid ${field}.`);
  const dot = value.indexOf(".");
  if (dot <= 0 || value.lastIndexOf(".") !== dot) throw new HttpError(400, `Invalid ${field}.`);
  requireBase64(value.slice(0, dot), field, 64);
  requireBase64(value.slice(dot + 1), field, 4000);
  return value;
}

function parseKeys(body: Record<string, unknown>) {
  const wrapIterations = body.wrapIterations;
  if (wrapIterations !== WRAP_ITERATIONS) throw new HttpError(400, "Unsupported key wrapping parameters.");
  return {
    ecdhPublic: requireBase64(body.ecdhPublic, "encryption key", 500),
    ecdsaPublic: requireBase64(body.ecdsaPublic, "signing key", 500),
    wrappedEcdh: requireWrapped(body.wrappedEcdh, "wrapped encryption key"),
    wrappedEcdsa: requireWrapped(body.wrappedEcdsa, "wrapped signing key"),
    wrapSalt: requireBase64(body.wrapSalt, "key salt", 80),
    wrapIterations,
  };
}

function decorate(conversation: NonNullable<ReturnType<WhisperDb["getConversation"]>>) {
  return { ...conversation, peerOnline: conversation.peer ? isOnline(conversation.peer.id) : false };
}

function parseCopies(value: unknown) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) {
    throw new HttpError(400, "Include every person in the group.");
  }
  return value.map((item) => {
    if (!item || typeof item !== "object") throw new HttpError(400, "Invalid group message.");
    const copy = item as Record<string, unknown>;
    return {
      userId: requireString(copy.userId, "Invalid group message.", 80),
      ephPublic: requireBase64(copy.ephPublic, "group key", 500),
      iv: requireBase64(copy.iv, "group iv", 64),
      ciphertext: requireBase64(copy.ciphertext, "group ciphertext", 48_000),
      signature: requireBase64(copy.signature, "group signature", 200),
    };
  });
}

async function assertGroupCopies(input: {
  copies: ReturnType<typeof parseCopies>;
  memberIds: string[];
  conversationId: string;
  senderId: string;
  nonce: string;
  senderEcdsaPublic: string;
}) {
  const seen = new Set(input.copies.map((copy) => copy.userId));
  if (seen.size !== input.copies.length || input.memberIds.length !== input.copies.length || input.memberIds.some((id) => !seen.has(id))) {
    throw new HttpError(400, "Include every person in the group.");
  }
  for (const copy of input.copies) {
    const valid = await verifyGroupCopy({
      conversationId: input.conversationId,
      senderId: input.senderId,
      nonce: input.nonce,
      memberId: copy.userId,
      bundle: { ephPublic: copy.ephPublic, iv: copy.iv, ciphertext: copy.ciphertext },
      signature: copy.signature,
      senderEcdsaPublic: input.senderEcdsaPublic,
    });
    if (!valid) throw new HttpError(400, "Message signature is invalid.");
  }
}

function parseBundle(value: unknown, field: string): CipherBundle {
  if (!value || typeof value !== "object") throw new HttpError(400, `Invalid ${field}.`);
  const bundle = value as Record<string, unknown>;
  return {
    ephPublic: requireBase64(bundle.ephPublic, `${field} key`, 500),
    iv: requireBase64(bundle.iv, `${field} iv`, 64),
    ciphertext: requireBase64(bundle.ciphertext, `${field} ciphertext`, 48_000),
  };
}

function currentUser(req: Request, db: WhisperDb): UserRow {
  const header = req.header("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
  if (!token) throw new HttpError(401, "Please sign in again.");
  const user = db.userForSession(token);
  if (!user) throw new HttpError(401, "Please sign in again.");
  return user;
}

function sessionResponse(db: WhisperDb, user: UserRow) {
  return { token: db.createSession(user.id), user: db.toAccount(user) };
}

function usernameFromEmail(db: WhisperDb, email: string) {
  const local = email.split("@")[0] ?? "user";
  let base = local.toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 16);
  if (base.length < 3) base = (`user${base}`).slice(0, 16);
  let username = base;
  let suffix = 1;
  while (db.getUserByUsername(username)) {
    const tail = String(suffix);
    username = `${base.slice(0, 20 - tail.length)}${tail}`;
    suffix += 1;
  }
  return username;
}

function publishKeys(db: WhisperDb, user: AccountUser) {
  notifyUsers(db.listPeerIds(user.id), {
    type: "keys",
    userId: user.id,
    ecdhPublic: user.ecdhPublic,
    ecdsaPublic: user.ecdsaPublic,
  });
}

const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_CIPHER_BYTES = MAX_FILE_BYTES + 16;
const expressRaw = express.raw({ type: "application/octet-stream", limit: "9mb" });

function attachmentPath(filesDir: string, id: string) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
    throw new HttpError(404, "File not found.");
  }
  const root = path.resolve(filesDir);
  const full = path.resolve(root, id);
  if (!full.startsWith(root + path.sep)) throw new HttpError(404, "File not found.");
  return full;
}

export function registerRoutes(app: Express, db: WhisperDb, filesDir: string) {
  function publishPersonalized(conversationId: string, messageId: string, type: "message" | "edit") {
    for (const memberId of db.listMemberIds(conversationId)) {
      const message = db.getMessageFor(messageId, memberId);
      if (message) sendToUser(memberId, { type, message });
    }
  }

  function publishToMembers(conversationId: string, event: object) {
    for (const memberId of db.listMemberIds(conversationId)) sendToUser(memberId, event);
  }

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true });
  });

  app.get("/api/config", (_req, res) => {
    res.json({ googleEnabled: googleEnabled() });
  });

  app.post(
    "/api/auth/register",
    asyncRoute(async (req, res) => {
      if (!rateLimit(`register:${clientIp(req)}`, 20, 10 * 60 * 1000)) {
        throw new HttpError(429, "Too many attempts. Wait a few minutes and try again.");
      }
      const body = req.body as Record<string, unknown>;
      const username = normalizeUsername(body.username);
      const displayName = normalizeDisplayName(body.displayName, username);
      const authVerifier = requireBase64(body.authVerifier, "login verifier", 100);
      const keys = parseKeys(body);
      if (db.getUserByUsername(username)) throw new HttpError(409, "That username is taken.");
      try {
        const user = db.createPasswordUser({
          username,
          displayName,
          passwordHash: hashVerifier(authVerifier),
          keys,
        });
        res.status(201).json(sessionResponse(db, user));
      } catch (error) {
        if (String(error).includes("UNIQUE")) throw new HttpError(409, "That username is taken.");
        throw error;
      }
    }),
  );

  app.post(
    "/api/auth/login",
    asyncRoute(async (req, res) => {
      if (!rateLimit(`login:${clientIp(req)}`, 30, 10 * 60 * 1000)) {
        throw new HttpError(429, "Too many attempts. Wait a few minutes and try again.");
      }
      const body = req.body as Record<string, unknown>;
      const username = normalizeUsername(body.username);
      const authVerifier = requireBase64(body.authVerifier, "login verifier", 100);
      const user = db.getUserByUsername(username);
      const stored = user?.password_hash ?? hashVerifier("missing-account");
      const matches = verifierMatches(authVerifier, stored);
      if (!user?.password_hash || !matches) {
        throw new HttpError(401, "Incorrect username or password.");
      }
      res.json(sessionResponse(db, user));
    }),
  );

  app.post(
    "/api/auth/exchange",
    asyncRoute(async (req, res) => {
      const code = requireString((req.body as { code?: unknown }).code, "Sign-in code is invalid.", 200);
      const token = consumeExchangeCode(code);
      if (!token) throw new HttpError(401, "Sign-in expired. Try Google again.");
      const user = db.userForSession(token);
      if (!user) throw new HttpError(401, "Sign-in expired. Try Google again.");
      res.json({ token, user: db.toAccount(user) });
    }),
  );

  app.post(
    "/api/auth/confirm",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const authVerifier = requireBase64((req.body as { authVerifier?: unknown }).authVerifier, "login verifier", 100);
      if (!user.password_hash || !verifierMatches(authVerifier, user.password_hash)) {
        throw new HttpError(401, "That password doesn't match this account.");
      }
      res.json({ ok: true });
    }),
  );

  app.post(
    "/api/auth/logout",
    asyncRoute(async (req, res) => {
      const header = req.header("authorization") ?? "";
      const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
      if (token) db.deleteSession(token);
      res.json({ ok: true });
    }),
  );

  app.get(
    "/api/auth/me",
    asyncRoute(async (req, res) => {
      res.json({ user: db.toAccount(currentUser(req, db)) });
    }),
  );

  app.get("/api/auth/google", (_req, res) => {
    if (!googleEnabled()) {
      res.redirect(`${clientOrigin()}/?auth_error=google_disabled`);
      return;
    }
    res.redirect(beginGoogleLogin());
  });

  app.get(
    "/api/auth/google/callback",
    asyncRoute(async (req, res) => {
      const origin = clientOrigin();
      try {
        const code = typeof req.query.code === "string" ? req.query.code : "";
        const state = typeof req.query.state === "string" ? req.query.state : "";
        if (!code || !consumeGoogleState(state)) {
          res.redirect(`${origin}/?auth_error=google`);
          return;
        }
        const profile = await exchangeGoogleCode(code);
        let user = db.getUserByGoogleSub(profile.sub);
        if (!user) {
          const emailName = profile.email.split("@")[0] ?? "Google user";
          const googleName = profile.name.replace(/[\u0000-\u001f]/g, "").trim().replace(/\s+/g, " ");
          user = db.createGoogleUser({
            username: usernameFromEmail(db, profile.email),
            displayName: (googleName || emailName).slice(0, 40),
            googleSub: profile.sub,
            email: profile.email,
          });
        }
        const token = db.createSession(user.id);
        res.redirect(`${origin}/?code=${createExchangeCode(token)}`);
      } catch (error) {
        console.error(error);
        res.redirect(`${origin}/?auth_error=google`);
      }
    }),
  );

  app.post(
    "/api/keys",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      if (user.ecdh_public) throw new HttpError(409, "Encryption keys are already set.");
      const saved = db.saveKeys(user.id, parseKeys(req.body as Record<string, unknown>));
      const account = db.toAccount(saved);
      publishKeys(db, account);
      res.json({ user: account });
    }),
  );

  app.post(
    "/api/keys/reset",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const saved = db.saveKeys(user.id, parseKeys(req.body as Record<string, unknown>));
      const account = db.toAccount(saved);
      publishKeys(db, account);
      res.json({ user: account });
    }),
  );

  app.get(
    "/api/users/search",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const query = requireString(req.query.q, "Enter a username.", 20).toLowerCase();
      res.json({ users: db.searchUsers(user.id, query) });
    }),
  );

  app.get(
    "/api/conversations",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const conversations = db.listConversations(user.id).map((conversation) => decorate(conversation));
      res.json({ conversations });
    }),
  );

  app.post(
    "/api/conversations",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const username = normalizeUsername((req.body as { username?: unknown }).username);
      if (username === user.username) throw new HttpError(400, "Choose someone else to message.");
      const peer = db.getUserByUsername(username);
      if (!peer) throw new HttpError(404, "No one uses that username.");
      const conversationId = db.openDirectConversation(user.id, peer.id);
      const conversation = db.getConversation(conversationId, user.id);
      res.status(201).json({ conversation: conversation ? decorate(conversation) : null });
    }),
  );

  app.post(
    "/api/groups",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      if (!user.ecdsa_public || !user.ecdh_public) throw new HttpError(409, "Set up encryption before starting a group.");
      const body = req.body as { title?: unknown; usernames?: unknown };
      const title = requireString(body.title, "Name the group.", 40).replace(/\s+/g, " ");
      if (/[\u0000-\u001f]/.test(title)) throw new HttpError(400, "Name the group.");
      if (!Array.isArray(body.usernames)) throw new HttpError(400, "Add at least two people.");
      const usernames = [...new Set(body.usernames.map((name) => normalizeUsername(name)))];
      if (usernames.length < 2 || usernames.length > 15) throw new HttpError(400, "Add between 2 and 15 people.");
      if (usernames.includes(user.username)) throw new HttpError(400, "You are already in the group.");
      const memberIds: string[] = [];
      for (const username of usernames) {
        const person = db.getUserByUsername(username);
        if (!person) throw new HttpError(404, `No one uses ${username}.`);
        if (!person.ecdh_public || !person.ecdsa_public) throw new HttpError(409, `${person.display_name} hasn't finished setting up encryption yet.`);
        memberIds.push(person.id);
      }
      const conversationId = db.createGroup({ ownerId: user.id, title, memberIds });
      const memberIdsAll = db.listMemberIds(conversationId);
      for (const memberId of memberIdsAll) {
        const conversation = db.getConversation(conversationId, memberId);
        if (conversation) sendToUser(memberId, { type: "conversation", conversation: decorate(conversation) });
      }
      const mine = db.getConversation(conversationId, user.id);
      res.status(201).json({ conversation: mine ? decorate(mine) : null });
    }),
  );

  app.post(
    "/api/groups/:id/members",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const conversation = db.getConversation(req.params.id, user.id);
      if (!conversation || conversation.kind !== "group") throw new HttpError(404, "Group not found.");
      const username = normalizeUsername((req.body as { username?: unknown }).username);
      if (username === user.username) throw new HttpError(400, "You are already in the group.");
      const person = db.getUserByUsername(username);
      if (!person) throw new HttpError(404, "No one uses that username.");
      if (!person.ecdh_public || !person.ecdsa_public) throw new HttpError(409, "That person hasn't finished setting up encryption yet.");
      if (db.listMemberIds(conversation.id).includes(person.id)) throw new HttpError(409, "That person is already in the group.");
      const added = db.addMember(conversation.id, person.id);
      if (!added) throw new HttpError(409, "This group is full.");
      for (const memberId of db.listMemberIds(conversation.id)) {
        const next = db.getConversation(conversation.id, memberId);
        if (next) sendToUser(memberId, { type: "conversation", conversation: decorate(next) });
      }
      const mine = db.getConversation(conversation.id, user.id);
      res.status(201).json({ conversation: mine ? decorate(mine) : null });
    }),
  );

  app.delete(
    "/api/groups/:id/members",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const conversation = db.getConversation(req.params.id, user.id);
      if (!conversation || conversation.kind !== "group") throw new HttpError(404, "Group not found.");
      db.removeMember(conversation.id, user.id);
      sendToUser(user.id, { type: "removed", conversationId: conversation.id });
      for (const memberId of db.listMemberIds(conversation.id)) {
        const next = db.getConversation(conversation.id, memberId);
        if (next) sendToUser(memberId, { type: "conversation", conversation: decorate(next) });
      }
      res.json({ ok: true });
    }),
  );

  app.get(
    "/api/conversations/:id/messages",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const conversationId = req.params.id;
      if (!db.isMember(conversationId, user.id)) throw new HttpError(404, "Chat not found.");
      const before = typeof req.query.before === "string" && req.query.before ? req.query.before : null;
      res.json(db.listMessages(conversationId, user.id, before, 40));
    }),
  );

  app.post(
    "/api/conversations/:id/attachments",
    expressRaw,
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      if (!rateLimit(`upload:${user.id}`, 20, 60 * 1000)) throw new HttpError(429, "Sending too fast. Pause for a moment.");
      const conversationId = req.params.id;
      if (!db.isMember(conversationId, user.id)) throw new HttpError(404, "Chat not found.");
      const body = req.body;
      if (!Buffer.isBuffer(body) || body.length === 0) throw new HttpError(400, "The encrypted file was empty.");
      if (body.length > MAX_CIPHER_BYTES) throw new HttpError(413, "That file is larger than 8 MB.");
      const id = randomUUID();
      const full = attachmentPath(filesDir, id);
      await writeFile(full, body);
      try {
        db.insertAttachment({ id, conversationId, senderId: user.id, byteLength: body.length });
      } catch (error) {
        await unlink(full).catch(() => undefined);
        throw error;
      }
      res.status(201).json({ id });
    }),
  );

  app.get(
    "/api/conversations/:id/attachments/:attachmentId",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const conversationId = req.params.id;
      const attachmentId = req.params.attachmentId;
      if (!db.isMember(conversationId, user.id)) throw new HttpError(404, "File not found.");
      const row = db.getAttachment(attachmentId);
      if (!row || row.conversation_id !== conversationId) throw new HttpError(404, "File not found.");
      const bytes = await readFile(attachmentPath(filesDir, row.id));
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Length", String(bytes.length));
      res.setHeader("Cache-Control", "private, no-store");
      res.send(bytes);
    }),
  );

  app.post(
    "/api/conversations/:id/messages",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      if (!rateLimit(`send:${user.id}`, 60, 60 * 1000)) throw new HttpError(429, "Sending too fast. Pause for a moment.");
      const conversationId = req.params.id;
      const conversation = db.getConversation(conversationId, user.id);
      if (!conversation) throw new HttpError(404, "Chat not found.");
      if (!user.ecdsa_public || !user.ecdh_public) throw new HttpError(409, "Set up encryption before sending.");
      const body = req.body as Record<string, unknown>;
      if (conversation.kind === "group") {
        const nonce = requireBase64(body.nonce, "nonce", 80);
        const copies = parseCopies(body.copies);
        await assertGroupCopies({
          copies,
          memberIds: db.listMemberIds(conversationId),
          conversationId,
          senderId: user.id,
          nonce,
          senderEcdsaPublic: user.ecdsa_public,
        });
        let message;
        try {
          message = db.insertGroupMessage({ conversationId, senderId: user.id, nonce, copies });
        } catch (error) {
          if (String(error).includes("UNIQUE")) throw new HttpError(409, "That message was already sent.");
          throw error;
        }
        if (!message) throw new HttpError(400, "Include every person in the group.");
        publishPersonalized(conversationId, message.id, "message");
        res.status(201).json({ message: db.getMessageFor(message.id, user.id) });
        return;
      }
      if (!conversation.peer?.keysReady || !conversation.peer.ecdhPublic) {
        throw new HttpError(409, "That person hasn't finished setting up encryption yet.");
      }
      const envelope: MessageEnvelope = {
        nonce: requireBase64(body.nonce, "nonce", 80),
        forRecipient: parseBundle(body.forRecipient, "recipient copy"),
        forSender: parseBundle(body.forSender, "sender copy"),
        signature: requireBase64(body.signature, "signature", 200),
      };
      const valid = await verifyEnvelope({
        envelope,
        conversationId,
        senderId: user.id,
        senderEcdsaPublic: user.ecdsa_public,
      });
      if (!valid) throw new HttpError(400, "Message signature is invalid.");
      let message;
      try {
        message = db.insertMessage({
          conversationId,
          senderId: user.id,
          nonce: envelope.nonce,
          forRecipient: envelope.forRecipient,
          forSender: envelope.forSender,
          signature: envelope.signature,
        });
      } catch (error) {
        if (String(error).includes("UNIQUE")) throw new HttpError(409, "That message was already sent.");
        throw error;
      }
      publishPersonalized(conversationId, message.id, "message");
      res.status(201).json({ message });
    }),
  );

  app.put(
    "/api/conversations/:id/messages/:messageId",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      if (!rateLimit(`edit:${user.id}`, 30, 60 * 1000)) throw new HttpError(429, "Editing too fast. Pause for a moment.");
      const conversationId = req.params.id;
      const conversation = db.getConversation(conversationId, user.id);
      if (!conversation) throw new HttpError(404, "Chat not found.");
      if (!user.ecdsa_public || !user.ecdh_public) throw new HttpError(409, "Set up encryption before editing.");
      const existing = db.getMessage(req.params.messageId);
      if (!existing || existing.conversationId !== conversationId || existing.senderId !== user.id) {
        throw new HttpError(404, "Message not found.");
      }
      const body = req.body as Record<string, unknown>;
      if (conversation.kind === "group") {
        const nonce = requireBase64(body.nonce, "nonce", 80);
        if (nonce !== existing.nonce) throw new HttpError(400, "That edit doesn't match this message.");
        const copies = parseCopies(body.copies);
        await assertGroupCopies({
          copies,
          memberIds: db.listMemberIds(conversationId),
          conversationId,
          senderId: user.id,
          nonce,
          senderEcdsaPublic: user.ecdsa_public,
        });
        const message = db.replaceGroupMessage({
          conversationId,
          messageId: existing.id,
          senderId: user.id,
          nonce,
          copies,
        });
        if (!message) throw new HttpError(404, "Message not found.");
        publishPersonalized(conversationId, message.id, "edit");
        res.json({ message: db.getMessageFor(message.id, user.id) });
        return;
      }
      const envelope: MessageEnvelope = {
        nonce: requireBase64(body.nonce, "nonce", 80),
        forRecipient: parseBundle(body.forRecipient, "recipient copy"),
        forSender: parseBundle(body.forSender, "sender copy"),
        signature: requireBase64(body.signature, "signature", 200),
      };
      if (envelope.nonce !== existing.nonce) throw new HttpError(400, "That edit doesn't match this message.");
      const valid = await verifyEnvelope({
        envelope,
        conversationId,
        senderId: user.id,
        senderEcdsaPublic: user.ecdsa_public,
      });
      if (!valid) throw new HttpError(400, "Message signature is invalid.");
      const message = db.replaceMessage({
        conversationId,
        messageId: existing.id,
        senderId: user.id,
        nonce: existing.nonce,
        forRecipient: envelope.forRecipient,
        forSender: envelope.forSender,
        signature: envelope.signature,
      });
      if (!message) throw new HttpError(404, "Message not found.");
      publishPersonalized(conversationId, message.id, "edit");
      res.json({ message });
    }),
  );

  app.delete(
    "/api/conversations/:id/messages/:messageId",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const conversationId = req.params.id;
      const conversation = db.getConversation(conversationId, user.id);
      if (!conversation) throw new HttpError(404, "Chat not found.");
      const removed = db.deleteMessage({
        conversationId,
        messageId: req.params.messageId,
        senderId: user.id,
      });
      if (!removed) throw new HttpError(404, "Message not found.");
      const attachmentId = (req.body as { attachmentId?: unknown } | undefined)?.attachmentId;
      if (typeof attachmentId === "string" && attachmentId) {
        const row = db.getAttachment(attachmentId);
        if (row && row.conversation_id === conversationId && row.sender_id === user.id) {
          db.deleteAttachment(attachmentId);
          await unlink(attachmentPath(filesDir, attachmentId)).catch(() => undefined);
        }
      }
      const event = {
        type: "delete" as const,
        conversationId,
        messageId: removed.message.id,
        nonce: removed.message.nonce,
        senderId: user.id,
        lastMessageAt: removed.lastMessageAt,
      };
      for (const memberId of db.listMemberIds(conversationId)) {
        sendToUser(memberId, memberId === user.id ? event : { ...event, unreadCount: db.unreadFor(conversationId, memberId) });
      }
      res.json({ ok: true, lastMessageAt: removed.lastMessageAt });
    }),
  );

  app.post(
    "/api/conversations/:id/messages/:messageId/collect",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const conversationId = req.params.id;
      const conversation = db.getConversation(conversationId, user.id);
      if (!conversation) throw new HttpError(404, "Chat not found.");
      const collects = (req.body as { collects?: unknown }).collects;
      if (typeof collects !== "boolean") throw new HttpError(400, "Choose whether this message collects replies.");
      const message = db.setCollectsReplies(conversationId, req.params.messageId, collects);
      if (!message) throw new HttpError(404, "Message not found.");
      publishToMembers(conversationId, {
        type: "collect",
        conversationId,
        messageId: message.id,
        nonce: message.nonce,
        collects,
      });
      res.json({ message });
    }),
  );

  app.post(
    "/api/conversations/:id/read",
    asyncRoute(async (req, res) => {
      const user = currentUser(req, db);
      const conversationId = req.params.id;
      const conversation = db.getConversation(conversationId, user.id);
      if (!conversation) throw new HttpError(404, "Chat not found.");
      const messageId = requireString((req.body as { messageId?: unknown }).messageId, "Missing message.", 80);
      const message = db.getMessage(messageId);
      if (!message || message.conversationId !== conversationId) throw new HttpError(404, "Message not found.");
      const lastReadAt = db.markRead(conversationId, user.id, message.createdAt);
      if (conversation.kind === "direct" && conversation.peer) {
        notifyUsers([conversation.peer.id], { type: "read", conversationId, userId: user.id, lastReadAt });
      }
      res.json({ lastReadAt });
    }),
  );
}
