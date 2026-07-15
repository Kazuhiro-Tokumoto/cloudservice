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

export async function downloadFile(path: string): Promise<Blob> {
  const res = await request(
    `/api/files/download?path=${encodeURIComponent(path)}`,
  );
  return res.blob();
}

export async function readTextFile(path: string): Promise<string> {
  const blob = await downloadFile(path);
  return blob.text();
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

export async function listUsers(): Promise<string[]> {
  const res = await request("/api/users");
  return res.json();
}

export async function listShares(): Promise<ShareList> {
  const res = await request("/api/shares");
  return res.json();
}

export async function createShare(
  path: string,
  targetUser: string,
  expiresDays: number,
): Promise<{ share: Share; url?: string }> {
  const res = await request("/api/shares", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      path,
      target_user: targetUser,
      expires_days: expiresDays,
    }),
  });
  return res.json();
}

export async function deleteShare(id: string): Promise<void> {
  await request(`/api/shares/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function downloadShared(id: string): Promise<Blob> {
  const res = await request(`/api/shared/download?id=${encodeURIComponent(id)}`);
  return res.blob();
}
