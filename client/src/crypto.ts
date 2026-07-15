// 認証キーの導出。
// ユーザー名とパスワードから SHA-256("username:password") を計算し、
// その 16 進文字列を「秘密鍵(認証キー)」としてサーバーに送る。
// 生パスワードはブラウザの外に出ない。サーバー側 auth.DeriveAuthKey と同じ計算。
export async function deriveAuthKey(
  username: string,
  password: string,
): Promise<string> {
  const data = new TextEncoder().encode(`${username}:${password}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
