// エンドツーエンド暗号化の中核。
//
// 鍵の構成:
//   パスワード --PBKDF2--> [認証キー(サーバーへ送信) | 包み鍵(ブラウザ内のみ)]
//   包み鍵 --AES-GCM--> マスター鍵(ランダム 32B)・ECDH 秘密鍵 を暗号化してサーバーに保管
//   ファイルごとにランダムなファイル鍵で AES-GCM 暗号化し、
//   ファイル鍵をマスター鍵で包んでファイル先頭に埋め込む。
//   → サーバーはどの鍵も持たないため、ファイルの中身を一切読めない。
//
// 共有:
//   ユーザー共有: ファイル鍵を共有先の ECDH 公開鍵で包み直して共有レコードに保存(ECIES)
//   リンク共有:   ファイル鍵を URL のフラグメント(#k=...)に載せる。
//                 フラグメントはサーバーに送信されないため、リンクを知る人だけが復号できる。

const PBKDF2_ITERATIONS = 310000; // サーバー側 auth.PBKDF2Iterations と一致させること
const textEncoder = new TextEncoder();

// --- バイト列ヘルパー ---

export function toB64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toB64Url(buf: Uint8Array): string {
  return toB64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64Url(s: string): Uint8Array {
  return fromB64(s.replace(/-/g, "+").replace(/_/g, "/"));
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// --- AES-GCM の小道具(iv12 || 暗号文 の形式で扱う) ---

async function aesEncrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data as BufferSource);
  return concat(iv, new Uint8Array(ct));
}

async function aesDecrypt(key: CryptoKey, blob: Uint8Array): Promise<Uint8Array> {
  const iv = blob.slice(0, 12);
  const ct = blob.slice(12);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct as BufferSource);
  return new Uint8Array(pt);
}

// --- パスワードからの鍵導出 ---

export interface DerivedKeys {
  /** サーバーへ送るログイン用の秘密鍵(hex 64 文字)。PBKDF2 出力の前半 32 バイト。 */
  authKey: string;
  /** 鍵バンドルの暗号化に使う包み鍵。PBKDF2 出力の後半 32 バイト。ブラウザの外へ出ない。 */
  wrapKey: CryptoKey;
}

export async function deriveKeys(
  username: string,
  password: string,
): Promise<DerivedKeys> {
  const base = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: textEncoder.encode(`cloudservice/v2:${username}`),
        iterations: PBKDF2_ITERATIONS,
      },
      base,
      512,
    ),
  );
  const wrapKey = await crypto.subtle.importKey(
    "raw",
    bits.slice(32) as BufferSource,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  );
  return { authKey: toHex(bits.slice(0, 32)), wrapKey };
}

// --- 鍵バンドル(サーバーに保管する暗号化済み鍵の入れ物) ---

export interface KeyBundle {
  v: number;
  public_key: string; // ECDH P-256 公開鍵 (SPKI, base64) — 平文で OK
  enc_private_key: string; // 包み鍵で暗号化した秘密鍵 (PKCS#8)
  enc_master_key: string; // 包み鍵で暗号化したマスター鍵 (32B)
}

export interface UserKeys {
  masterKey: CryptoKey; // AES-GCM。ファイル鍵の包み/解き用
  privateKey: CryptoKey; // ECDH。共有されたファイル鍵の解き用
  publicKeySpki: string;
}

const ECDH_PARAMS = { name: "ECDH", namedCurve: "P-256" } as const;

async function importMasterKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

async function importPrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", pkcs8 as BufferSource, ECDH_PARAMS, false, [
    "deriveBits",
  ]);
}

/** 初回ログイン時に新しい鍵一式を生成する。 */
export async function createKeyBundle(
  wrapKey: CryptoKey,
): Promise<{ bundle: KeyBundle; keys: UserKeys }> {
  const masterRaw = crypto.getRandomValues(new Uint8Array(32));
  const pair = await crypto.subtle.generateKey(ECDH_PARAMS, true, ["deriveBits"]);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));

  const bundle: KeyBundle = {
    v: 2,
    public_key: toB64(spki),
    enc_private_key: toB64(await aesEncrypt(wrapKey, pkcs8)),
    enc_master_key: toB64(await aesEncrypt(wrapKey, masterRaw)),
  };
  const keys: UserKeys = {
    masterKey: await importMasterKey(masterRaw),
    privateKey: await importPrivateKey(pkcs8),
    publicKeySpki: bundle.public_key,
  };
  return { bundle, keys };
}

/** サーバーから取得した鍵バンドルを包み鍵で開く。パスワード不一致なら例外。 */
export async function openKeyBundle(
  wrapKey: CryptoKey,
  bundle: KeyBundle,
): Promise<UserKeys> {
  const masterRaw = await aesDecrypt(wrapKey, fromB64(bundle.enc_master_key));
  const pkcs8 = await aesDecrypt(wrapKey, fromB64(bundle.enc_private_key));
  return {
    masterKey: await importMasterKey(masterRaw),
    privateKey: await importPrivateKey(pkcs8),
    publicKeySpki: bundle.public_key,
  };
}

/** パスワード変更用: 既存バンドルを開いて中身(生バイト)を取り出し、新しい包み鍵で包み直す。 */
export async function rewrapKeyBundle(
  oldWrapKey: CryptoKey,
  newWrapKey: CryptoKey,
  bundle: KeyBundle,
): Promise<KeyBundle> {
  const masterRaw = await aesDecrypt(oldWrapKey, fromB64(bundle.enc_master_key));
  const pkcs8 = await aesDecrypt(oldWrapKey, fromB64(bundle.enc_private_key));
  return {
    v: 2,
    public_key: bundle.public_key,
    enc_private_key: toB64(await aesEncrypt(newWrapKey, pkcs8)),
    enc_master_key: toB64(await aesEncrypt(newWrapKey, masterRaw)),
  };
}

// --- ファイルの暗号化フォーマット ---
//
//   "CSE1" (4B) | 包み鍵長 (2B BE) | 包んだファイル鍵 (iv12+ct32+tag16 = 60B) | iv (12B) | AES-GCM 暗号文
//
// 「包んだファイル鍵」はマスター鍵で AES-GCM 暗号化したファイル鍵。
// 共有相手はこの部分は解けないが、共有レコード/URL フラグメント経由で
// 別途受け取ったファイル鍵で暗号文部分を復号する。

const MAGIC = new Uint8Array([0x43, 0x53, 0x45, 0x31]); // "CSE1"
export const BLOB_OVERHEAD = 4 + 2 + 60 + 12 + 16; // 表示サイズ補正用

interface ParsedBlob {
  wrappedKey: Uint8Array;
  rest: Uint8Array; // iv12 || ct
}

export function parseFileBlob(buf: Uint8Array): ParsedBlob {
  if (
    buf.length < 6 ||
    !MAGIC.every((b, i) => buf[i] === b)
  ) {
    throw new Error("暗号化ファイルの形式ではありません");
  }
  const wkLen = (buf[4] << 8) | buf[5];
  if (buf.length < 6 + wkLen) throw new Error("暗号化ファイルが壊れています");
  return {
    wrappedKey: buf.slice(6, 6 + wkLen),
    rest: buf.slice(6 + wkLen),
  };
}

/** ファイルを暗号化してアップロード用ブロブを作る。 */
export async function encryptFile(
  masterKey: CryptoKey,
  data: Uint8Array,
): Promise<Blob> {
  const fileKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  const fileKey = await crypto.subtle.importKey(
    "raw",
    fileKeyRaw as BufferSource,
    "AES-GCM",
    false,
    ["encrypt"],
  );
  const wrapped = await aesEncrypt(masterKey, fileKeyRaw);
  const body = await aesEncrypt(fileKey, data);
  const header = new Uint8Array([...MAGIC, wrapped.length >> 8, wrapped.length & 0xff]);
  return new Blob([header as BufferSource, wrapped as BufferSource, body as BufferSource]);
}

/** 自分のファイルをマスター鍵で復号する。 */
export async function decryptFileWithMaster(
  masterKey: CryptoKey,
  buf: Uint8Array,
): Promise<Uint8Array> {
  const { wrappedKey, rest } = parseFileBlob(buf);
  const fileKeyRaw = await aesDecrypt(masterKey, wrappedKey);
  return decryptBody(fileKeyRaw, rest);
}

/** 共有用: ブロブ(先頭部分だけで可)からファイル鍵の生バイトを取り出す。 */
export async function unwrapFileKey(
  masterKey: CryptoKey,
  headerBuf: Uint8Array,
): Promise<Uint8Array> {
  const { wrappedKey } = parseFileBlob(headerBuf);
  return aesDecrypt(masterKey, wrappedKey);
}

/** 受け取ったファイル鍵(生バイト)でブロブを復号する(共有ファイル用)。 */
export async function decryptFileWithRawKey(
  fileKeyRaw: Uint8Array,
  buf: Uint8Array,
): Promise<Uint8Array> {
  const { rest } = parseFileBlob(buf);
  return decryptBody(fileKeyRaw, rest);
}

async function decryptBody(fileKeyRaw: Uint8Array, rest: Uint8Array): Promise<Uint8Array> {
  const fileKey = await crypto.subtle.importKey(
    "raw",
    fileKeyRaw as BufferSource,
    "AES-GCM",
    false,
    ["decrypt"],
  );
  return aesDecrypt(fileKey, rest);
}

// --- メール用: 生鍵での小さなデータの暗号化/復号 ---
// メールは 1 通ごとにランダムなメール鍵を作り、件名と本文を個別に暗号化する。
// メール鍵は宛先の公開鍵(受信箱用)と自分の公開鍵(送信済み用)でそれぞれ包む。

export function newRawKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function encryptBytesWithRawKey(
  rawKey: Uint8Array,
  data: Uint8Array,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    rawKey as BufferSource,
    "AES-GCM",
    false,
    ["encrypt"],
  );
  return toB64(await aesEncrypt(key, data));
}

export async function decryptBytesWithRawKey(
  rawKey: Uint8Array,
  b64: string,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    rawKey as BufferSource,
    "AES-GCM",
    false,
    ["decrypt"],
  );
  return aesDecrypt(key, fromB64(b64));
}

// --- ユーザー共有のための鍵の包み直し (ECIES: ECDH + HKDF + AES-GCM) ---
//
// 形式: 送信側の一時公開鍵 (raw 65B) || iv12 || 包んだファイル鍵

async function sharedAesKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<CryptoKey> {
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: textEncoder.encode("cloudservice/share/v2"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** ファイル鍵を共有先の公開鍵(SPKI base64)で包む。 */
export async function wrapKeyForUser(
  fileKeyRaw: Uint8Array,
  recipientPublicKeySpki: string,
): Promise<string> {
  const recipientPub = await crypto.subtle.importKey(
    "spki",
    fromB64(recipientPublicKeySpki) as BufferSource,
    ECDH_PARAMS,
    false,
    [],
  );
  const eph = await crypto.subtle.generateKey(ECDH_PARAMS, true, ["deriveBits"]);
  const kek = await sharedAesKey(eph.privateKey, recipientPub);
  const ephRaw = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey)); // 65B
  const wrapped = await aesEncrypt(kek, fileKeyRaw);
  return toB64(concat(ephRaw, wrapped));
}

/** 自分宛に包まれたファイル鍵を自分の秘密鍵で解く。 */
export async function unwrapKeyFromUser(
  privateKey: CryptoKey,
  wrappedB64: string,
): Promise<Uint8Array> {
  const data = fromB64(wrappedB64);
  const ephPub = await crypto.subtle.importKey(
    "raw",
    data.slice(0, 65) as BufferSource,
    ECDH_PARAMS,
    false,
    [],
  );
  const kek = await sharedAesKey(privateKey, ephPub);
  return aesDecrypt(kek, data.slice(65));
}
