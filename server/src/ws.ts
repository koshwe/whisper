import type { Server } from "node:http";
import { WebSocketServer, type WebSocket } from "ws";
import type { WhisperDb } from "./db.ts";
import { addSocket, isOnline, notifyUsers, removeSocket, sendToUser } from "./hub.ts";

type AuthedSocket = WebSocket & { userId?: string };

export function attachWebSocket(server: Server, db: WhisperDb) {
  const wss = new WebSocketServer({ server, path: "/ws", maxPayload: 4096 });

  wss.on("connection", (socket: AuthedSocket) => {
    let userId = "";
    const timeout = setTimeout(() => {
      if (!userId) socket.close(4001, "unauthorized");
    }, 5000);

    socket.on("message", (raw) => {
      let parsed: { type?: string; token?: string; conversationId?: string; active?: boolean; messageId?: string };
      try {
        parsed = JSON.parse(raw.toString()) as typeof parsed;
      } catch {
        return;
      }

      if (!userId) {
        if (parsed.type !== "auth" || typeof parsed.token !== "string") return;
        const user = db.userForSession(parsed.token);
        if (!user) {
          socket.close(4001, "unauthorized");
          return;
        }
        userId = user.id;
        socket.userId = user.id;
        clearTimeout(timeout);
        const becameOnline = addSocket(user.id, socket);
        const peerIds = db.listPeerIds(user.id);
        sendToUser(user.id, { type: "hello", onlineUserIds: peerIds.filter((id) => isOnline(id) && id !== user.id) });
        if (becameOnline) notifyUsers(peerIds, { type: "presence", userId: user.id, online: true });
        return;
      }

      if (parsed.type === "typing" && typeof parsed.conversationId === "string") {
        const conversation = db.getConversation(parsed.conversationId, userId);
        if (!conversation) return;
        const event = {
          type: "typing",
          conversationId: conversation.id,
          userId,
          active: Boolean(parsed.active),
        };
        for (const memberId of db.listMemberIds(conversation.id)) {
          if (memberId !== userId) sendToUser(memberId, event);
        }
        return;
      }

      if (parsed.type === "read" && typeof parsed.conversationId === "string" && typeof parsed.messageId === "string") {
        const conversation = db.getConversation(parsed.conversationId, userId);
        const message = db.getMessage(parsed.messageId);
        if (!conversation || !message || message.conversationId !== conversation.id) return;
        const lastReadAt = db.markRead(conversation.id, userId, message.createdAt);
        if (conversation.kind === "direct" && conversation.peer) {
          sendToUser(conversation.peer.id, { type: "read", conversationId: conversation.id, userId, lastReadAt });
        }
      }
    });

    socket.on("close", () => {
      clearTimeout(timeout);
      if (!userId) return;
      const lastSocket = removeSocket(userId, socket);
      if (lastSocket) notifyUsers(db.listPeerIds(userId), { type: "presence", userId, online: false });
    });
  });

  return wss;
}
