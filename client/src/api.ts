// サーバー API クライアント。全リクエストは Bearer トークンで認証する。

export interface Entry {
  name: string;
  path: string;
  is_dir: boolean;
  size: number;
  mod_time: string;
}

export interface Share {
  id: string;
  owner: string;
  path: string;
  target_user: string;
  created_at: string;
  expires_at: string;
  wrapped_key?: string;
}

export interface KeyBundle {
  v: number;
  public_key: string;
  enc_private_key: string;
  enc_master_key: string;
}

export interface MailMessage {
  id: string;
  folder: "inbox" | "sent";
  from: string;
  to: string;
  created_at: string;
  enc_subject: string;
  enc_body?: string;
  wrapped_key: string;
  size?: number;
}

export interface Quota {
  used: number;
  limit: number;
}

export interface ShareList {
  mine: Share[];
  received: Share[];
}

const TOKEN_KEY = "cloudservice.token";
const USER_KEY = "cloudservice.username";

export function savedSession(): { token: string; username: string } | null {
  const token = localStorage.getItem(TOKEN_KEY);
  const username = localStorage.getItem(USER_KEY);
  return token && username ? { token, username } : null;
}

export function clearSession(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

let token = "";
export function setToken(t: string): void {
  token = t;
}

async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body.error) msg = body.error;
    } catch {
      /* JSON でないエラー本文は無視 */
    }
    if (res.status === 401) clearSession();
    throw new Error(msg);
  }
  return res;
}

export async function login(
  username: string,
  authKey: string,
): Promise<string> {
  const res = await request("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, auth_key: authKey }),
  });
  const body = await res.json();
  token = body.token;
  localStorage.setItem(TOKEN_KEY, body.token);
  localStorage.setItem(USER_KEY, body.username);
  return body.username;
}

export async function listFiles(path: string): Promise<Entry[]> {
  const res = await request(`/api/files?path=${encodeURIComponent(path)}`);
  return res.json();
}

export async function uploadFile(path: string, file: Blob): Promise<void> {
  await request(`/api/files/upload?path=${encodeURIComponent(path)}`, {
    method: "PUT",
    body: file,
  });
}

export async function downloadFile(path: string): Promise<Uint8Array> {
  const res = await request(
    `/api/files/download?path=${encodeURIComponent(path)}`,
  );
  return new Uint8Array(await res.arrayBuffer());
}

// 暗号化ヘッダー(包んだファイル鍵)だけ読みたいとき用。先頭バイトのみ取得する。
export async function downloadFileHeader(path: string): Promise<Uint8Array> {
  const res = await request(
    `/api/files/download?path=${encodeURIComponent(path)}&limit=512`,
  );
  return new Uint8Array(await res.arrayBuffer());
}

export async function deleteFile(path: string): Promise<void> {
  await request(`/api/files?path=${encodeURIComponent(path)}`, {
    method: "DELETE",
  });
}

export async function mkdir(path: string): Promise<void> {
  await request("/api/files/mkdir", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path }),
  });
}

export async function renameFile(from: string, to: string): Promise<void> {
  await request("/api/files/rename", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ from, to }),
  });
}

export async function listUsers(): Promise<string[]> {
  const res = await request("/api/users");
  return res.json();
}

// --- 鍵管理 ---

export async function getKeyBundle(): Promise<KeyBundle | null> {
  try {
    const res = await request("/api/keys");
    return await res.json();
  } catch {
    return null; // 未登録(初回ログイン)
  }
}

export async function putKeyBundle(
  bundle: KeyBundle,
  force = false,
): Promise<void> {
  await request(`/api/keys${force ? "?force=1" : ""}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(bundle),
  });
}

export async function getUserPublicKey(username: string): Promise<string> {
  const res = await request(`/api/keys/user/${encodeURIComponent(username)}`);
  const body = await res.json();
  return body.public_key;
}

export async function changePassword(
  newAuthKey: string,
  bundle: KeyBundle,
): Promise<void> {
  await request("/api/password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ new_auth_key: newAuthKey, key_bundle: bundle }),
  });
}

export async function listShares(): Promise<ShareList> {
  const res = await request("/api/shares");
  return res.json();
}

export async function createShare(
  path: string,
  targetUser: string,
  expiresDays: number,
  wrappedKey: string,
): Promise<{ share: Share; url?: string }> {
  const res = await request("/api/shares", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      path,
      target_user: targetUser,
      expires_days: expiresDays,
      wrapped_key: wrappedKey,
    }),
  });
  return res.json();
}

export async function deleteShare(id: string): Promise<void> {
  await request(`/api/shares/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function downloadShared(id: string): Promise<Uint8Array> {
  const res = await request(`/api/shared/download?id=${encodeURIComponent(id)}`);
  return new Uint8Array(await res.arrayBuffer());
}

// --- メール ---

export async function sendMail(payload: {
  to: string;
  enc_subject: string;
  enc_body: string;
  wrapped_key_to: string;
  wrapped_key_self: string;
}): Promise<void> {
  await request("/api/mail", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function listMail(folder: "inbox" | "sent"): Promise<MailMessage[]> {
  const res = await request(`/api/mail?folder=${folder}`);
  return res.json();
}

export async function getMail(id: string): Promise<MailMessage> {
  const res = await request(`/api/mail/${encodeURIComponent(id)}`);
  return res.json();
}

export async function deleteMail(id: string): Promise<void> {
  await request(`/api/mail/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function getQuota(): Promise<Quota> {
  const res = await request("/api/quota");
  return res.json();
}

// リンク共有のブロブ取得(認証不要)。ファイル名は Content-Disposition から取る。
export async function downloadPublicShare(
  token: string,
): Promise<{ data: Uint8Array; filename: string }> {
  const res = await fetch(`/api/public/share/${encodeURIComponent(token)}`);
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body.error) msg = body.error;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  const cd = res.headers.get("Content-Disposition") ?? "";
  const m = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cd);
  const filename = m ? decodeURIComponent(m[1].replace(/"$/, "")) : "download";
  return { data: new Uint8Array(await res.arrayBuffer()), filename };
}
