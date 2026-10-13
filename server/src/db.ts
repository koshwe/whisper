import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

export type UserRow = {
  id: string;
  username: string;
  display_name: string;
  password_hash: string | null;
  google_sub: string | null;
  email: string | null;
  ecdh_public: string | null;
  ecdsa_public: string | null;
  wrapped_ecdh: string | null;
  wrapped_ecdsa: string | null;
  wrap_salt: string | null;
  wrap_iterations: number | null;
  created_at: string;
};

export type MessageRow = {
  id: string;
  conversation_id: string;
  sender_id: string;
  nonce: string;
  recipient_eph_public: string;
  recipient_iv: string;
  recipient_ciphertext: string;
  sender_eph_public: string;
  sender_iv: string;
  sender_ciphertext: string;
  signature: string;
  created_at: string;
  collects_replies: number;
  edited_at: string | null;
};

export type PublicUser = {
  id: string;
  username: string;
  displayName: string;
  keysReady: boolean;
  ecdhPublic: string | null;
  ecdsaPublic: string | null;
};

export type AccountUser = PublicUser & {
  provider: "password" | "google";
  wrappedEcdh: string | null;
  wrappedEcdsa: string | null;
  wrapSalt: string | null;
  wrapIterations: number | null;
};

export type StoredMessage = {
  id: string;
  conversationId: string;
  senderId: string;
  nonce: string;
  createdAt: string;
  forRecipient: { ephPublic: string; iv: string; ciphertext: string };
  forSender: { ephPublic: string; iv: string; ciphertext: string };
  signature: string;
  collectsReplies: boolean;
  editedAt: string | null;
  forMe: { ephPublic: string; iv: string; ciphertext: string } | null;
};

export type ConversationSummary = {
  id: string;
  kind: "direct" | "group";
  title: string | null;
  createdAt: string;
  lastMessageAt: string | null;
  unreadCount: number;
  peerLastReadAt: string | null;
  peer: PublicUser | null;
  members: PublicUser[];
  lastMessage: StoredMessage | null;
};

export type KeyBackup = {
  ecdhPublic: string;
  ecdsaPublic: string;
  wrappedEcdh: string;
  wrappedEcdsa: string;
  wrapSalt: string;
  wrapIterations: number;
};

const SESSION_MS = 30 * 24 * 60 * 60 * 1000;

function toPublic(user: UserRow): PublicUser {
  return {
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    keysReady: Boolean(user.ecdh_public && user.ecdsa_public && user.wrapped_ecdh),
    ecdhPublic: user.ecdh_public,
    ecdsaPublic: user.ecdsa_public,
  };
}

function toAccount(user: UserRow): AccountUser {
  return {
    ...toPublic(user),
    provider: user.google_sub ? "google" : "password",
    wrappedEcdh: user.wrapped_ecdh,
    wrappedEcdsa: user.wrapped_ecdsa,
    wrapSalt: user.wrap_salt,
    wrapIterations: user.wrap_iterations,
  };
}

function toMessage(row: MessageRow): StoredMessage {
  return {
    id: row.id,
    conversationId: row.conversation_id,
    senderId: row.sender_id,
    nonce: row.nonce,
    createdAt: row.created_at,
    forRecipient: {
      ephPublic: row.recipient_eph_public,
      iv: row.recipient_iv,
      ciphertext: row.recipient_ciphertext,
    },
    forSender: {
      ephPublic: row.sender_eph_public,
      iv: row.sender_iv,
      ciphertext: row.sender_ciphertext,
    },
    signature: row.signature,
    collectsReplies: row.collects_replies === 1,
    editedAt: row.edited_at,
    forMe: null,
  };
}

export function openDatabase(dbPath: string) {
  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 3000;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      password_hash TEXT,
      google_sub TEXT UNIQUE,
      email TEXT,
      ecdh_public TEXT,
      ecdsa_public TEXT,
      wrapped_ecdh TEXT,
      wrapped_ecdsa TEXT,
      wrap_salt TEXT,
      wrap_iterations INTEGER,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS conversations (
      id TEXT PRIMARY KEY,
      direct_key TEXT NOT NULL UNIQUE,
      kind TEXT NOT NULL DEFAULT 'direct',
      title TEXT,
      created_at TEXT NOT NULL,
      last_message_at TEXT
    );

    CREATE TABLE IF NOT EXISTS members (
      conversation_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      last_read_at TEXT,
      PRIMARY KEY (conversation_id, user_id),
      FOREIGN KEY (conversation_id) REFERENCES conversations(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      sender_id TEXT NOT NULL,
      nonce TEXT NOT NULL,
      recipient_eph_public TEXT NOT NULL,
      recipient_iv TEXT NOT NULL,
      recipient_ciphertext TEXT NOT NULL,
      sender_eph_public TEXT NOT NULL,
      sender_iv TEXT NOT NULL,
      sender_ciphertext TEXT NOT NULL,
      signature TEXT NOT NULL,
      created_at TEXT NOT NULL,
      collects_replies INTEGER NOT NULL DEFAULT 0,
      edited_at TEXT,
      UNIQUE (conversation_id, nonce),
      FOREIGN KEY (conversation_id) REFERENCES conversations(id),
      FOREIGN KEY (sender_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_members_user ON members(user_id);

    CREATE TABLE IF NOT EXISTS attachments (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      sender_id TEXT NOT NULL,
      byte_length INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (conversation_id) REFERENCES conversations(id),
      FOREIGN KEY (sender_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS message_copies (
      message_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      eph_public TEXT NOT NULL,
      iv TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      signature TEXT NOT NULL,
      PRIMARY KEY (message_id, user_id),
      FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);
  const messageColumns = db.prepare("PRAGMA table_info(messages)").all() as Array<{ name: string }>;
  if (!messageColumns.some((column) => column.name === "collects_replies")) {
    db.exec("ALTER TABLE messages ADD COLUMN collects_replies INTEGER NOT NULL DEFAULT 0");
  }
  if (!messageColumns.some((column) => column.name === "edited_at")) {
    db.exec("ALTER TABLE messages ADD COLUMN edited_at TEXT");
  }
  const conversationColumns = db.prepare("PRAGMA table_info(conversations)").all() as Array<{ name: string }>;
  if (!conversationColumns.some((column) => column.name === "kind")) {
    db.exec("ALTER TABLE conversations ADD COLUMN kind TEXT NOT NULL DEFAULT 'direct'");
  }
  if (!conversationColumns.some((column) => column.name === "title")) {
    db.exec("ALTER TABLE conversations ADD COLUMN title TEXT");
  }

  const insertUser = db.prepare(`
    INSERT INTO users (
      id, username, display_name, password_hash, google_sub, email,
      ecdh_public, ecdsa_public, wrapped_ecdh, wrapped_ecdsa, wrap_salt, wrap_iterations, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const userById = db.prepare("SELECT * FROM users WHERE id = ?");
  const userByUsername = db.prepare("SELECT * FROM users WHERE username = ?");
  const userByGoogle = db.prepare("SELECT * FROM users WHERE google_sub = ?");
  const insertSession = db.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)");
  const deleteExpired = db.prepare("DELETE FROM sessions WHERE expires_at < ?");
  const sessionUser = db.prepare(`
    SELECT users.* FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token = ? AND sessions.expires_at > ?
  `);
  const deleteSession = db.prepare("DELETE FROM sessions WHERE token = ?");
  const searchUsers = db.prepare(`
    SELECT * FROM users
    WHERE id != ? AND (username LIKE ? ESCAPE '\\' OR lower(display_name) LIKE ? ESCAPE '\\')
    ORDER BY username
    LIMIT 8
  `);
  const listOtherUsers = db.prepare("SELECT * FROM users WHERE id != ? ORDER BY username LIMIT ?");
  const conversationByKey = db.prepare("SELECT id FROM conversations WHERE direct_key = ?");
  const insertConversation = db.prepare(
    "INSERT INTO conversations (id, direct_key, kind, title, created_at, last_message_at) VALUES (?, ?, ?, ?, ?, NULL)",
  );
  const insertMember = db.prepare(
    "INSERT INTO members (conversation_id, user_id, last_read_at) VALUES (?, ?, NULL)",
  );
  const deleteMember = db.prepare("DELETE FROM members WHERE conversation_id = ? AND user_id = ?");
  const memberExists = db.prepare("SELECT 1 AS ok FROM members WHERE conversation_id = ? AND user_id = ?");
  const memberCount = db.prepare("SELECT COUNT(*) AS count FROM members WHERE conversation_id = ?");
  const listConversationRows = db.prepare(`
    SELECT id, kind, title, created_at, last_message_at
    FROM conversations
    WHERE id IN (SELECT conversation_id FROM members WHERE user_id = ?)
    ORDER BY COALESCE(last_message_at, created_at) DESC
  `);
  const otherMembers = db.prepare(`
    SELECT users.* FROM users
    JOIN members ON members.user_id = users.id
    WHERE members.conversation_id = ? AND users.id != ?
    ORDER BY users.username
  `);
  const memberIdRows = db.prepare("SELECT user_id AS id FROM members WHERE conversation_id = ?");
  const conversationKind = db.prepare("SELECT kind FROM conversations WHERE id = ?");
  const memberRead = db.prepare("SELECT last_read_at FROM members WHERE conversation_id = ? AND user_id = ?");
  const lastMessage = db.prepare(
    "SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 1",
  );
  const groupLastMessage = db.prepare(`
    SELECT messages.* FROM messages
    JOIN message_copies ON message_copies.message_id = messages.id AND message_copies.user_id = ?
    WHERE messages.conversation_id = ?
    ORDER BY messages.created_at DESC
    LIMIT 1
  `);
  const unreadCount = db.prepare(`
    SELECT COUNT(*) AS count FROM messages
    WHERE conversation_id = ? AND sender_id != ? AND created_at > COALESCE(?, '')
  `);
  const groupUnread = db.prepare(`
    SELECT COUNT(*) AS count FROM messages
    JOIN message_copies ON message_copies.message_id = messages.id AND message_copies.user_id = ?
    WHERE messages.conversation_id = ? AND messages.sender_id != ? AND messages.created_at > COALESCE(?, '')
  `);
  const copyForUser = db.prepare("SELECT eph_public, iv, ciphertext, signature FROM message_copies WHERE message_id = ? AND user_id = ?");
  const insertCopy = db.prepare(
    "INSERT INTO message_copies (message_id, user_id, eph_public, iv, ciphertext, signature) VALUES (?, ?, ?, ?, ?, ?)",
  );
  const deleteCopies = db.prepare("DELETE FROM message_copies WHERE message_id = ?");
  const insertMessage = db.prepare(`
    INSERT INTO messages (
      id, conversation_id, sender_id, nonce,
      recipient_eph_public, recipient_iv, recipient_ciphertext,
      sender_eph_public, sender_iv, sender_ciphertext,
      signature, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const touchConversation = db.prepare("UPDATE conversations SET last_message_at = ? WHERE id = ?");
  const messageById = db.prepare("SELECT * FROM messages WHERE id = ?");
  const setCollects = db.prepare("UPDATE messages SET collects_replies = ? WHERE id = ? AND conversation_id = ?");
  const replaceMessageRow = db.prepare(`
    UPDATE messages SET
      recipient_eph_public = ?, recipient_iv = ?, recipient_ciphertext = ?,
      sender_eph_public = ?, sender_iv = ?, sender_ciphertext = ?,
      signature = ?, edited_at = ?
    WHERE id = ? AND conversation_id = ? AND sender_id = ? AND nonce = ?
  `);
  const deleteMessageRow = db.prepare("DELETE FROM messages WHERE id = ? AND conversation_id = ? AND sender_id = ?");
  const deleteAttachmentRow = db.prepare("DELETE FROM attachments WHERE id = ?");
  const listMessages = db.prepare(`
    SELECT * FROM messages
    WHERE conversation_id = ? AND (? IS NULL OR created_at < ?)
    ORDER BY created_at DESC
    LIMIT ?
  `);
  const listGroupMessages = db.prepare(`
    SELECT messages.* FROM messages
    JOIN message_copies ON message_copies.message_id = messages.id AND message_copies.user_id = ?
    WHERE messages.conversation_id = ? AND (? IS NULL OR messages.created_at < ?)
    ORDER BY messages.created_at DESC
    LIMIT ?
  `);
  const markRead = db.prepare(`
    UPDATE members
    SET last_read_at = CASE
      WHEN last_read_at IS NULL OR last_read_at < ? THEN ?
      ELSE last_read_at
    END
    WHERE conversation_id = ? AND user_id = ?
  `);
  const peerIds = db.prepare(`
    SELECT other.user_id AS id
    FROM members mine
    JOIN members other ON other.conversation_id = mine.conversation_id AND other.user_id != mine.user_id
    WHERE mine.user_id = ?
  `);
  const updateKeys = db.prepare(`
    UPDATE users
    SET ecdh_public = ?, ecdsa_public = ?, wrapped_ecdh = ?, wrapped_ecdsa = ?, wrap_salt = ?, wrap_iterations = ?
    WHERE id = ?
  `);
  const insertAttachment = db.prepare(
    "INSERT INTO attachments (id, conversation_id, sender_id, byte_length, created_at) VALUES (?, ?, ?, ?, ?)",
  );
  const attachmentById = db.prepare("SELECT id, conversation_id, sender_id, byte_length, created_at FROM attachments WHERE id = ?");

  function withTransaction<T>(fn: () => T): T {
    db.exec("BEGIN");
    try {
      const result = fn();
      db.exec("COMMIT");
      return result;
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }

  function requireUser(id: string): UserRow {
    const user = userById.get(id) as UserRow | undefined;
    if (!user) throw new Error("User disappeared.");
    return user;
  }

  type ConversationRow = { id: string; kind: string | null; title: string | null; created_at: string; last_message_at: string | null };
  type CopyRow = { eph_public: string; iv: string; ciphertext: string; signature: string };

  function presentRow(row: MessageRow, viewerId: string, kind: "direct" | "group"): StoredMessage {
    const message = toMessage(row);
    if (kind !== "group") return message;
    const copy = copyForUser.get(row.id, viewerId) as CopyRow | undefined;
    if (!copy) return message;
    return {
      ...message,
      forMe: { ephPublic: copy.eph_public, iv: copy.iv, ciphertext: copy.ciphertext },
      signature: copy.signature,
    };
  }

  function kindOf(conversationId: string): "direct" | "group" {
    const row = conversationKind.get(conversationId) as { kind: string | null } | undefined;
    return row?.kind === "group" ? "group" : "direct";
  }

  function hydrateConversation(conversation: ConversationRow, userId: string): ConversationSummary | null {
    const kind = conversation.kind === "group" ? "group" : "direct";
    const others = (otherMembers.all(conversation.id, userId) as UserRow[]).map(toPublic);
    if (kind === "direct" && others.length !== 1) return null;
    const peer = kind === "direct" ? others[0] : null;
    const mine = memberRead.get(conversation.id, userId) as { last_read_at: string | null } | undefined;
    const readAt = mine?.last_read_at ?? null;
    const unread = kind === "group"
      ? (groupUnread.get(userId, conversation.id, userId, readAt) as { count: number })
      : (unreadCount.get(conversation.id, userId, readAt) as { count: number });
    let peerLastReadAt: string | null = null;
    if (peer) {
      const theirs = memberRead.get(conversation.id, peer.id) as { last_read_at: string | null } | undefined;
      peerLastReadAt = theirs?.last_read_at ?? null;
    }
    const latest = kind === "group"
      ? (groupLastMessage.get(userId, conversation.id) as MessageRow | undefined)
      : (lastMessage.get(conversation.id) as MessageRow | undefined);
    return {
      id: conversation.id,
      kind,
      title: kind === "group" ? conversation.title : null,
      createdAt: conversation.created_at,
      lastMessageAt: conversation.last_message_at,
      unreadCount: Number(unread.count),
      peerLastReadAt,
      peer,
      members: others,
      lastMessage: latest ? presentRow(latest, userId, kind) : null,
    };
  }

  return {
    close() {
      db.close();
    },
    checkpoint() {
      db.exec("PRAGMA wal_checkpoint(FULL)");
    },
    toAccount,
    toPublic,
    toMessage,
    getUserById(id: string) {
      return (userById.get(id) as UserRow | undefined) ?? null;
    },
    getUserByUsername(username: string) {
      return (userByUsername.get(username) as UserRow | undefined) ?? null;
    },
    getUserByGoogleSub(sub: string) {
      return (userByGoogle.get(sub) as UserRow | undefined) ?? null;
    },
    createPasswordUser(input: {
      username: string;
      displayName: string;
      passwordHash: string;
      keys: KeyBackup;
    }) {
      const id = crypto.randomUUID();
      const now = new Date().toISOString();
      insertUser.run(
        id,
        input.username,
        input.displayName,
        input.passwordHash,
        null,
        null,
        input.keys.ecdhPublic,
        input.keys.ecdsaPublic,
        input.keys.wrappedEcdh,
        input.keys.wrappedEcdsa,
        input.keys.wrapSalt,
        input.keys.wrapIterations,
        now,
      );
      return requireUser(id);
    },
    createGoogleUser(input: { username: string; displayName: string; googleSub: string; email: string }) {
      const id = crypto.randomUUID();
      const now = new Date().toISOString();
      insertUser.run(id, input.username, input.displayName, null, input.googleSub, input.email, null, null, null, null, null, null, now);
      return requireUser(id);
    },
    saveKeys(userId: string, keys: KeyBackup) {
      updateKeys.run(keys.ecdhPublic, keys.ecdsaPublic, keys.wrappedEcdh, keys.wrappedEcdsa, keys.wrapSalt, keys.wrapIterations, userId);
      return requireUser(userId);
    },
    createSession(userId: string) {
      deleteExpired.run(Date.now());
      const token = randomBytes(32).toString("base64url");
      insertSession.run(token, userId, Date.now() + SESSION_MS);
      return token;
    },
    userForSession(token: string) {
      const user = sessionUser.get(token, Date.now()) as UserRow | undefined;
      return user ?? null;
    },
    deleteSession(token: string) {
      deleteSession.run(token);
    },
    searchUsers(userId: string, query: string) {
      const escaped = query.toLowerCase().replace(/[\\%_]/g, (character) => `\\${character}`);
      const pattern = `%${escaped}%`;
      return (searchUsers.all(userId, pattern, pattern) as UserRow[]).map(toPublic);
    },
    listOtherUsers(userId: string, limit = 50) {
      return (listOtherUsers.all(userId, limit) as UserRow[]).map(toPublic);
    },
    openDirectConversation(userA: string, userB: string) {
      const key = [userA, userB].sort().join(":");
      const existing = conversationByKey.get(key) as { id: string } | undefined;
      if (existing) return existing.id;
      const id = crypto.randomUUID();
      const now = new Date().toISOString();
      try {
        withTransaction(() => {
          insertConversation.run(id, key, "direct", null, now);
          insertMember.run(id, userA);
          insertMember.run(id, userB);
        });
      } catch (error) {
        const raced = conversationByKey.get(key) as { id: string } | undefined;
        if (raced) return raced.id;
        throw error;
      }
      return id;
    },
    isMember(conversationId: string, userId: string) {
      return Boolean(memberExists.get(conversationId, userId));
    },
    listConversations(userId: string) {
      const rows = listConversationRows.all(userId) as ConversationRow[];
      return rows
        .map((row) => hydrateConversation(row, userId))
        .filter((row): row is ConversationSummary => row !== null);
    },
    getConversation(conversationId: string, userId: string) {
      if (!memberExists.get(conversationId, userId)) return null;
      const row = db.prepare("SELECT id, kind, title, created_at, last_message_at FROM conversations WHERE id = ?").get(conversationId) as
        | ConversationRow
        | undefined;
      if (!row) return null;
      return hydrateConversation(row, userId);
    },
    listMemberIds(conversationId: string) {
      return (memberIdRows.all(conversationId) as Array<{ id: string }>).map((row) => row.id);
    },
    createGroup(input: { ownerId: string; title: string; memberIds: string[] }) {
      const id = crypto.randomUUID();
      const now = new Date().toISOString();
      withTransaction(() => {
        insertConversation.run(id, `group:${id}`, "group", input.title, now);
        insertMember.run(id, input.ownerId);
        for (const memberId of input.memberIds) insertMember.run(id, memberId);
      });
      return id;
    },
    addMember(conversationId: string, userId: string) {
      if (memberExists.get(conversationId, userId)) return false;
      const count = memberCount.get(conversationId) as { count: number };
      if (Number(count.count) >= 16) return false;
      insertMember.run(conversationId, userId);
      return true;
    },
    removeMember(conversationId: string, userId: string) {
      const removed = deleteMember.run(conversationId, userId);
      return removed.changes === 1;
    },
    insertMessage(input: {
      conversationId: string;
      senderId: string;
      nonce: string;
      forRecipient: { ephPublic: string; iv: string; ciphertext: string };
      forSender: { ephPublic: string; iv: string; ciphertext: string };
      signature: string;
    }) {
      const id = crypto.randomUUID();
      const createdAt = new Date().toISOString();
      withTransaction(() => {
        insertMessage.run(
          id,
          input.conversationId,
          input.senderId,
          input.nonce,
          input.forRecipient.ephPublic,
          input.forRecipient.iv,
          input.forRecipient.ciphertext,
          input.forSender.ephPublic,
          input.forSender.iv,
          input.forSender.ciphertext,
          input.signature,
          createdAt,
        );
        touchConversation.run(createdAt, input.conversationId);
      });
      return toMessage(messageById.get(id) as MessageRow);
    },
    listMessages(conversationId: string, userId: string, before: string | null, limit: number) {
      const kind = kindOf(conversationId);
      const rows = kind === "group"
        ? (listGroupMessages.all(userId, conversationId, before, before, limit + 1) as MessageRow[])
        : (listMessages.all(conversationId, before, before, limit + 1) as MessageRow[]);
      const hasMore = rows.length > limit;
      return {
        messages: rows.slice(0, limit).reverse().map((row) => presentRow(row, userId, kind)),
        hasMore,
      };
    },
    getMessage(messageId: string) {
      const row = messageById.get(messageId) as MessageRow | undefined;
      return row ? toMessage(row) : null;
    },
    getMessageFor(messageId: string, viewerId: string) {
      const row = messageById.get(messageId) as MessageRow | undefined;
      if (!row || !memberExists.get(row.conversation_id, viewerId)) return null;
      return presentRow(row, viewerId, kindOf(row.conversation_id));
    },
    insertGroupMessage(input: {
      conversationId: string;
      senderId: string;
      nonce: string;
      copies: Array<{ userId: string; ephPublic: string; iv: string; ciphertext: string; signature: string }>;
    }) {
      const senderCopy = input.copies.find((copy) => copy.userId === input.senderId);
      if (!senderCopy) return null;
      const id = crypto.randomUUID();
      const createdAt = new Date().toISOString();
      withTransaction(() => {
        insertMessage.run(
          id,
          input.conversationId,
          input.senderId,
          input.nonce,
          senderCopy.ephPublic,
          senderCopy.iv,
          senderCopy.ciphertext,
          senderCopy.ephPublic,
          senderCopy.iv,
          senderCopy.ciphertext,
          senderCopy.signature,
          createdAt,
        );
        for (const copy of input.copies) {
          insertCopy.run(id, copy.userId, copy.ephPublic, copy.iv, copy.ciphertext, copy.signature);
        }
        touchConversation.run(createdAt, input.conversationId);
      });
      return presentRow(messageById.get(id) as MessageRow, input.senderId, "group");
    },
    replaceGroupMessage(input: {
      conversationId: string;
      messageId: string;
      senderId: string;
      nonce: string;
      copies: Array<{ userId: string; ephPublic: string; iv: string; ciphertext: string; signature: string }>;
    }) {
      const senderCopy = input.copies.find((copy) => copy.userId === input.senderId);
      const existing = messageById.get(input.messageId) as MessageRow | undefined;
      if (!senderCopy || !existing || existing.conversation_id !== input.conversationId || existing.sender_id !== input.senderId || existing.nonce !== input.nonce) {
        return null;
      }
      const editedAt = new Date().toISOString();
      withTransaction(() => {
        replaceMessageRow.run(
          senderCopy.ephPublic,
          senderCopy.iv,
          senderCopy.ciphertext,
          senderCopy.ephPublic,
          senderCopy.iv,
          senderCopy.ciphertext,
          senderCopy.signature,
          editedAt,
          input.messageId,
          input.conversationId,
          input.senderId,
          input.nonce,
        );
        deleteCopies.run(input.messageId);
        for (const copy of input.copies) {
          insertCopy.run(input.messageId, copy.userId, copy.ephPublic, copy.iv, copy.ciphertext, copy.signature);
        }
      });
      return presentRow(messageById.get(input.messageId) as MessageRow, input.senderId, "group");
    },
    replaceMessage(input: {
      conversationId: string;
      messageId: string;
      senderId: string;
      nonce: string;
      forRecipient: { ephPublic: string; iv: string; ciphertext: string };
      forSender: { ephPublic: string; iv: string; ciphertext: string };
      signature: string;
    }) {
      const editedAt = new Date().toISOString();
      const updated = replaceMessageRow.run(
        input.forRecipient.ephPublic,
        input.forRecipient.iv,
        input.forRecipient.ciphertext,
        input.forSender.ephPublic,
        input.forSender.iv,
        input.forSender.ciphertext,
        input.signature,
        editedAt,
        input.messageId,
        input.conversationId,
        input.senderId,
        input.nonce,
      );
      if (updated.changes !== 1) return null;
      const row = messageById.get(input.messageId) as MessageRow | undefined;
      return row ? toMessage(row) : null;
    },
    setCollectsReplies(conversationId: string, messageId: string, collects: boolean) {
      const updated = setCollects.run(collects ? 1 : 0, messageId, conversationId);
      if (updated.changes !== 1) return null;
      const row = messageById.get(messageId) as MessageRow | undefined;
      return row ? toMessage(row) : null;
    },
    deleteMessage(input: { conversationId: string; messageId: string; senderId: string }) {
      const row = messageById.get(input.messageId) as MessageRow | undefined;
      if (!row || row.conversation_id !== input.conversationId || row.sender_id !== input.senderId) return null;
      const message = toMessage(row);
      let lastMessageAt: string | null = null;
      withTransaction(() => {
        deleteMessageRow.run(input.messageId, input.conversationId, input.senderId);
        const latest = lastMessage.get(input.conversationId) as MessageRow | undefined;
        lastMessageAt = latest?.created_at ?? null;
        touchConversation.run(lastMessageAt, input.conversationId);
      });
      return { message, lastMessageAt };
    },
    unreadFor(conversationId: string, userId: string) {
      const mine = memberRead.get(conversationId, userId) as { last_read_at: string | null } | undefined;
      const readAt = mine?.last_read_at ?? null;
      const unread = kindOf(conversationId) === "group"
        ? (groupUnread.get(userId, conversationId, userId, readAt) as { count: number })
        : (unreadCount.get(conversationId, userId, readAt) as { count: number });
      return Number(unread.count);
    },
    deleteAttachment(id: string) {
      deleteAttachmentRow.run(id);
    },
    markRead(conversationId: string, userId: string, createdAt: string) {
      markRead.run(createdAt, createdAt, conversationId, userId);
      const row = memberRead.get(conversationId, userId) as { last_read_at: string | null };
      return row.last_read_at;
    },
    listPeerIds(userId: string) {
      return (peerIds.all(userId) as Array<{ id: string }>).map((row) => row.id);
    },
    insertAttachment(input: { id: string; conversationId: string; senderId: string; byteLength: number }) {
      insertAttachment.run(input.id, input.conversationId, input.senderId, input.byteLength, new Date().toISOString());
    },
    getAttachment(id: string) {
      return (
        (attachmentById.get(id) as
          | { id: string; conversation_id: string; sender_id: string; byte_length: number; created_at: string }
          | undefined) ?? null
      );
    },
  };
}

export type WhisperDb = ReturnType<typeof openDatabase>;
