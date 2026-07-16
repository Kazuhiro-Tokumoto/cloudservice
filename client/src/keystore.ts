// ログイン中ユーザーの鍵(CryptoKey)を IndexedDB に保持する。
// CryptoKey は extractable=false のまま保存されるため、
// 保存された鍵から生バイトを取り出すことはできない(XSS 等への緩和策)。
import type { UserKeys } from "./crypto";

const DB_NAME = "cloudservice-keys";
const STORE = "keys";

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(
  mode: IDBTransactionMode,
  fn: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openDB().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const t = db.transaction(STORE, mode);
        const req = fn(t.objectStore(STORE));
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        t.oncomplete = () => db.close();
      }),
  );
}

export async function saveKeys(username: string, keys: UserKeys): Promise<void> {
  await tx("readwrite", (s) => s.put(keys, username));
}

export async function loadKeys(username: string): Promise<UserKeys | null> {
  try {
    const v = await tx<UserKeys | undefined>("readonly", (s) => s.get(username));
    return v && v.masterKey && v.privateKey ? v : null;
  } catch {
    return null;
  }
}

export async function clearKeys(username: string): Promise<void> {
  try {
    await tx("readwrite", (s) => s.delete(username));
  } catch {
    /* 消せなくても致命的ではない */
  }
}
