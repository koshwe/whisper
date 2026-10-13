import { WebSocket } from "ws";

const sockets = new Map<string, Set<WebSocket>>();

export function addSocket(userId: string, socket: WebSocket) {
  const existing = sockets.get(userId) ?? new Set<WebSocket>();
  existing.add(socket);
  sockets.set(userId, existing);
  return existing.size === 1;
}

export function removeSocket(userId: string, socket: WebSocket) {
  const existing = sockets.get(userId);
  if (!existing) return true;
  existing.delete(socket);
  if (existing.size === 0) {
    sockets.delete(userId);
    return true;
  }
  return false;
}

export function isOnline(userId: string) {
  return sockets.has(userId);
}

export function sendToUser(userId: string, payload: unknown) {
  const existing = sockets.get(userId);
  if (!existing) return;
  const data = JSON.stringify(payload);
  for (const socket of existing) {
    if (socket.readyState === WebSocket.OPEN) socket.send(data);
  }
}

export function notifyUsers(userIds: string[], payload: unknown) {
  for (const userId of userIds) sendToUser(userId, payload);
}
