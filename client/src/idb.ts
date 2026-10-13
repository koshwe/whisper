import type { Identity } from "@whisper/shared";

const DB_NAME = "whisper-keys";
const STORE = "identities";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function finish(request: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    request.oncomplete = () => resolve();
    request.onerror = () => reject(request.error);
    request.onabort = () => reject(request.error);
  });
}

export async function saveIdentity(userId: string, identity: Identity) {
  const db = await openDb();
  const tx = db.transaction(STORE, "readwrite");
  tx.objectStore(STORE).put(identity, userId);
  await finish(tx);
  db.close();
}

export async function loadIdentity(userId: string): Promise<Identity | null> {
  const db = await openDb();
  const identity = await new Promise<Identity | null>((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const request = tx.objectStore(STORE).get(userId);
    request.onsuccess = () => resolve((request.result as Identity | undefined) ?? null);
    request.onerror = () => reject(request.error);
  });
  db.close();
  return identity;
}

export async function clearIdentity(userId: string) {
  const db = await openDb();
  const tx = db.transaction(STORE, "readwrite");
  tx.objectStore(STORE).delete(userId);
  await finish(tx);
  db.close();
}
