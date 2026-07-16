// クラウドサービス Web クライアント本体。
// すべてのファイルはブラウザ内で暗号化されてからアップロードされ、
// サーバー(管理者を含む)はファイルの中身を読めない。
import * as api from "./api";
import {
  BLOB_OVERHEAD,
  createKeyBundle,
  decryptBytesWithRawKey,
  decryptFileWithMaster,
  decryptFileWithRawKey,
  deriveKeys,
  encryptBytesWithRawKey,
  encryptFile,
  fromB64Url,
  newRawKey,
  openKeyBundle,
  rewrapKeyBundle,
  toB64Url,
  unwrapFileKey,
  unwrapKeyFromUser,
  wrapKeyForUser,
  type UserKeys,
} from "./crypto";
import { clearKeys, loadKeys, saveKeys } from "./keystore";

const app = document.getElementById("app")!;

let currentUser = "";
let currentPath = "";
let userKeys: UserKeys | null = null;

// --- ユーティリティ ---

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else e.setAttribute(k, v);
  }
  e.append(...children);
  return e;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

function fmtSize(encryptedSize: number): string {
  return fmtBytes(Math.max(0, encryptedSize - BLOB_OVERHEAD));
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString("ja-JP");
}

function saveBytes(data: Uint8Array, filename: string): void {
  const url = URL.createObjectURL(new Blob([data as BufferSource]));
  const a = el("a", { href: url, download: filename });
  a.click();
  URL.revokeObjectURL(url);
}

function showError(msg: string): void {
  const banner = document.getElementById("error-banner");
  if (banner) {
    banner.textContent = msg;
    banner.hidden = false;
  } else {
    alert(msg);
  }
}

function hideError(): void {
  const banner = document.getElementById("error-banner");
  if (banner) banner.hidden = true;
}

async function run(action: () => Promise<void>): Promise<void> {
  try {
    hideError();
    await action();
  } catch (e) {
    showError(e instanceof Error ? e.message : String(e));
    if (!api.savedSession() && currentUser) {
      // トークン失効 → ログイン画面へ
      currentUser = "";
      userKeys = null;
      renderLogin();
    }
  }
}

function closeDialog(dialog: HTMLDialogElement): void {
  dialog.close();
  dialog.remove();
}

// --- ログイン ---

function renderLogin(notice = ""): void {
  const username = el("input", {
    type: "text",
    placeholder: "ユーザー名",
    autocomplete: "username",
  });
  const password = el("input", {
    type: "password",
    placeholder: "パスワード",
    autocomplete: "current-password",
  });
  const msg = el("div", { class: "note" }, notice);
  const btn = el("button", { class: "primary", type: "submit" }, "ログイン");

  const form = el("form", {}, username, password, btn, msg);
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    btn.disabled = true;
    msg.textContent = "鍵を導出しています…";
    try {
      const { authKey, wrapKey } = await deriveKeys(
        username.value,
        password.value,
      );
      currentUser = await api.login(username.value, authKey);

      // 鍵バンドル: 初回なら生成、2 回目以降は包み鍵で開く
      msg.textContent = "暗号鍵を準備しています…";
      const existing = await api.getKeyBundle();
      if (!existing) {
        const { bundle, keys } = await createKeyBundle(wrapKey);
        await api.putKeyBundle(bundle);
        userKeys = keys;
      } else {
        try {
          userKeys = await openKeyBundle(wrapKey, existing);
        } catch {
          // userctl でパスワードリセットされた等で包み鍵が合わない
          if (
            !confirm(
              "保存されている暗号鍵をこのパスワードで開けませんでした。\n" +
                "(管理者によるパスワードリセット後などに起こります)\n\n" +
                "鍵を作り直しますか? 作り直すと今までの暗号化ファイルは読めなくなります。",
            )
          ) {
            throw new Error("鍵を開けなかったためログインを中止しました");
          }
          const { bundle, keys } = await createKeyBundle(wrapKey);
          await api.putKeyBundle(bundle, true);
          userKeys = keys;
        }
      }
      await saveKeys(currentUser, userKeys);
      currentPath = "";
      await renderMain();
    } catch (e) {
      msg.textContent = e instanceof Error ? e.message : String(e);
    } finally {
      btn.disabled = false;
    }
  };

  app.replaceChildren(
    el(
      "div",
      { class: "login-wrap" },
      el(
        "div",
        { class: "login-card" },
        el("h1", {}, "クラウドサービス"),
        form,
        el(
          "div",
          { class: "note" },
          "ファイルはブラウザ内で暗号化され、サーバー管理者もその中身を読めません。" +
            "パスワードを忘れるとファイルを復元できないので注意してください。" +
            "アカウントは管理者に発行してもらってください。",
        ),
      ),
    ),
  );
}

// --- メイン画面 ---

async function renderMain(): Promise<void> {
  const errorBanner = el("div", { class: "error-banner", id: "error-banner" });
  errorBanner.hidden = true;

  const passwordBtn = el("button", { class: "ghost" }, "パスワード変更");
  passwordBtn.onclick = () => openPasswordDialog();

  const logoutBtn = el("button", { class: "ghost" }, "ログアウト");
  logoutBtn.onclick = async () => {
    await clearKeys(currentUser);
    api.clearSession();
    api.setToken("");
    currentUser = "";
    userKeys = null;
    renderLogin();
  };

  // タブ: ファイル / メール / 共有
  const tabs: { id: string; label: string; refresh: () => Promise<void> }[] = [
    { id: "files-panel", label: "ファイル", refresh: refreshFiles },
    { id: "mail-panel", label: "メール", refresh: refreshMail },
    { id: "shares-panel", label: "共有", refresh: refreshShares },
  ];
  const nav = el("nav", { class: "tabs" });
  const showTab = (id: string) => {
    for (const t of tabs) {
      document.getElementById(t.id)!.hidden = t.id !== id;
    }
    nav.querySelectorAll("button").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === id);
    });
    const tab = tabs.find((t) => t.id === id)!;
    run(tab.refresh);
  };
  for (const t of tabs) {
    const btn = el("button", { "data-tab": t.id }, t.label);
    btn.onclick = () => showTab(t.id);
    nav.append(btn);
  }

  app.replaceChildren(
    el(
      "header",
      { class: "topbar" },
      el("h1", {}, "クラウドサービス"),
      el(
        "div",
        { class: "userbox" },
        el("span", { class: "lock", title: "エンドツーエンド暗号化" }, "🔒"),
        `${currentUser} さん`,
        passwordBtn,
        logoutBtn,
      ),
    ),
    nav,
    el(
      "main",
      {},
      errorBanner,
      el("section", { class: "panel", id: "files-panel" }),
      el("section", { class: "panel", id: "mail-panel" }),
      el("section", { class: "panel", id: "shares-panel" }),
    ),
  );
  showTab("files-panel");
}

async function refreshFiles(): Promise<void> {
  const panel = document.getElementById("files-panel")!;
  const [entries, quota] = await Promise.all([
    api.listFiles(currentPath),
    api.getQuota(),
  ]);

  // 使用容量(ファイル + メールで 10GB まで)
  const pct = Math.min(100, (quota.used / quota.limit) * 100);
  const bar = el("span");
  bar.style.width = `${pct}%`;
  const quotaBox = el(
    "div",
    { class: "quota", title: "ファイルとメールの合計" },
    el("div", { class: "bar" }, bar),
    `${fmtBytes(quota.used)} / ${fmtBytes(quota.limit)} 使用中`,
  );

  // パンくずリスト
  const crumbs = el("div", { class: "breadcrumb" });
  const homeLink = el("button", { class: "link" }, "ホーム");
  homeLink.onclick = () => {
    currentPath = "";
    run(refreshFiles);
  };
  crumbs.append(homeLink);
  let acc = "";
  for (const part of currentPath.split("/").filter(Boolean)) {
    acc = acc ? `${acc}/${part}` : part;
    const target = acc;
    const btn = el("button", { class: "link" }, part);
    btn.onclick = () => {
      currentPath = target;
      run(refreshFiles);
    };
    crumbs.append(" / ", btn);
  }

  // ツールバー
  const fileInput = el("input", { type: "file" });
  fileInput.hidden = true;
  fileInput.multiple = true;
  fileInput.onchange = () =>
    run(async () => {
      for (const f of fileInput.files ?? []) {
        const dest = currentPath ? `${currentPath}/${f.name}` : f.name;
        const data = new Uint8Array(await f.arrayBuffer());
        const blob = await encryptFile(userKeys!.masterKey, data);
        await api.uploadFile(dest, blob);
      }
      fileInput.value = "";
      await refreshFiles();
    });
  const uploadBtn = el("button", { class: "primary" }, "アップロード");
  uploadBtn.onclick = () => fileInput.click();

  const mkdirBtn = el("button", {}, "フォルダ作成");
  mkdirBtn.onclick = () => {
    const name = prompt("フォルダ名を入力してください");
    if (!name) return;
    run(async () => {
      await api.mkdir(currentPath ? `${currentPath}/${name}` : name);
      await refreshFiles();
    });
  };

  const newFileBtn = el("button", {}, "テキスト作成");
  newFileBtn.onclick = () => {
    const name = prompt("ファイル名を入力してください", "memo.txt");
    if (!name) return;
    run(async () => {
      const dest = currentPath ? `${currentPath}/${name}` : name;
      const blob = await encryptFile(userKeys!.masterKey, new Uint8Array(0));
      await api.uploadFile(dest, blob);
      await refreshFiles();
      await openEditor(dest);
    });
  };

  const refreshBtn = el("button", {}, "更新");
  refreshBtn.onclick = () => run(refreshFiles);

  // 一括選択
  const selected = new Map<string, api.Entry>();
  const bulkCount = el("span", { class: "bulk-count" });
  const bulkDlBtn = el("button", {}, "一括ダウンロード");
  const bulkDelBtn = el("button", { class: "danger-btn" }, "一括削除");
  const updateBulk = () => {
    const n = selected.size;
    bulkDlBtn.disabled = bulkDelBtn.disabled = n === 0;
    bulkCount.textContent = n ? `${n} 件選択中` : "";
  };
  bulkDlBtn.onclick = () =>
    run(async () => {
      for (const entry of selected.values()) {
        if (!entry.is_dir) {
          await downloadAndSave(entry.path, entry.name);
        }
      }
    });
  bulkDelBtn.onclick = () => {
    if (!confirm(`選択した ${selected.size} 件を削除しますか?(フォルダは中身ごと消えます)`)) {
      return;
    }
    run(async () => {
      for (const path of selected.keys()) {
        await api.deleteFile(path);
      }
      await refreshFiles();
    });
  };

  // ファイル一覧
  const rowChecks: HTMLInputElement[] = [];
  const tbody = el("tbody");
  for (const entry of entries) {
    const check = el("input", { type: "checkbox" });
    check.onchange = () => {
      if (check.checked) selected.set(entry.path, entry);
      else selected.delete(entry.path);
      updateBulk();
    };
    rowChecks.push(check);
    const nameCell = el(
      "td",
      { class: "name-cell" },
      el("span", { class: "icon" }, entry.is_dir ? "📁" : "📄"),
      entry.name,
    );
    nameCell.onclick = () => {
      if (entry.is_dir) {
        currentPath = entry.path;
        run(refreshFiles);
      } else if (isTextFile(entry.name) && entry.size < 1024 * 1024) {
        run(() => openEditor(entry.path));
      } else {
        run(async () => downloadAndSave(entry.path, entry.name));
      }
    };

    const actions = el("td", { class: "actions" });
    if (!entry.is_dir) {
      const dl = el("button", { class: "link" }, "ダウンロード");
      dl.onclick = () => run(async () => downloadAndSave(entry.path, entry.name));
      const share = el("button", { class: "link" }, "共有");
      share.onclick = () => run(() => openShareDialog(entry.path));
      actions.append(dl, share);
    }
    const del = el("button", { class: "link danger" }, "削除");
    del.onclick = () => {
      if (!confirm(`「${entry.name}」を削除しますか?`)) return;
      run(async () => {
        await api.deleteFile(entry.path);
        await refreshFiles();
      });
    };
    actions.append(del);

    tbody.append(
      el(
        "tr",
        {},
        el("td", { class: "check-cell" }, check),
        nameCell,
        el("td", { class: "muted" }, entry.is_dir ? "—" : fmtSize(entry.size)),
        el("td", { class: "muted" }, fmtDate(entry.mod_time)),
        actions,
      ),
    );
  }

  // 全選択チェックボックス
  const checkAll = el("input", { type: "checkbox", title: "すべて選択" });
  checkAll.onchange = () => {
    selected.clear();
    for (let i = 0; i < entries.length; i++) {
      rowChecks[i].checked = checkAll.checked;
      if (checkAll.checked) selected.set(entries[i].path, entries[i]);
    }
    updateBulk();
  };

  const table = el(
    "table",
    {},
    el(
      "thead",
      {},
      el(
        "tr",
        {},
        el("th", { class: "check-cell" }, checkAll),
        el("th", {}, "名前"),
        el("th", {}, "サイズ"),
        el("th", {}, "更新日時"),
        el("th", {}, ""),
      ),
    ),
    tbody,
  );
  updateBulk();

  panel.replaceChildren(
    el("h2", {}, "マイファイル"),
    el(
      "div",
      { class: "toolbar" },
      uploadBtn,
      mkdirBtn,
      newFileBtn,
      refreshBtn,
      bulkDlBtn,
      bulkDelBtn,
      bulkCount,
      el("span", { class: "spacer" }),
      quotaBox,
      fileInput,
    ),
    crumbs,
    entries.length
      ? table
      : el("div", { class: "empty" }, "ファイルはありません"),
  );
}

async function downloadAndSave(path: string, name: string): Promise<void> {
  const blob = await api.downloadFile(path);
  const data = await decryptFileWithMaster(userKeys!.masterKey, blob);
  saveBytes(data, name);
}

function isTextFile(name: string): boolean {
  return /\.(txt|md|json|csv|log|yaml|yml|xml|html|css|js|ts|go|py|sh|conf|ini)$/i.test(
    name,
  );
}

// --- テキストエディタ ---

async function openEditor(path: string): Promise<void> {
  const blob = await api.downloadFile(path);
  const data = await decryptFileWithMaster(userKeys!.masterKey, blob);
  const content = new TextDecoder().decode(data);

  const dialog = el("dialog", { class: "wide" });
  const textarea = el("textarea", { rows: "16" }) as HTMLTextAreaElement;
  textarea.value = content;

  const saveBtn = el("button", { class: "primary", type: "button" }, "保存");
  saveBtn.onclick = () =>
    run(async () => {
      const enc = await encryptFile(
        userKeys!.masterKey,
        new TextEncoder().encode(textarea.value),
      );
      await api.uploadFile(path, enc);
      closeDialog(dialog);
      await refreshFiles();
    });
  const closeBtn = el("button", { type: "button" }, "閉じる");
  closeBtn.onclick = () => closeDialog(dialog);

  dialog.append(
    el("h2", {}, path),
    textarea,
    el("div", { class: "toolbar" }, saveBtn, closeBtn),
  );
  document.body.append(dialog);
  dialog.showModal();
}

// --- 共有 ---

async function openShareDialog(path: string): Promise<void> {
  const users = (await api.listUsers()).filter((u) => u !== currentUser);

  const dialog = el("dialog");
  const targetSelect = el("select");
  targetSelect.append(
    el("option", { value: "" }, "リンク共有(URL を知っている人が復号可)"),
  );
  for (const u of users) {
    targetSelect.append(el("option", { value: u }, `ユーザー: ${u}`));
  }
  const expires = el("input", { type: "number", min: "0", value: "0" });
  const result = el("div", { class: "share-url" });

  const createBtn = el(
    "button",
    { class: "primary", type: "button" },
    "共有を作成",
  );
  createBtn.onclick = () =>
    run(async () => {
      // ファイル先頭のヘッダーからファイル鍵を取り出す
      const header = await api.downloadFileHeader(path);
      const fileKeyRaw = await unwrapFileKey(userKeys!.masterKey, header);
      const days = Number(expires.value) || 0;

      if (targetSelect.value) {
        // ユーザー共有: 相手の公開鍵でファイル鍵を包み直す
        const pub = await api.getUserPublicKey(targetSelect.value);
        const wrapped = await wrapKeyForUser(fileKeyRaw, pub);
        await api.createShare(path, targetSelect.value, days, wrapped);
        result.textContent = `${targetSelect.value} さんに共有しました(相手だけが復号できます)`;
      } else {
        // リンク共有: 鍵は URL のフラグメントに載せる(サーバーへは送信されない)
        const res = await api.createShare(path, "", days, "");
        const full = `${location.origin}${res.url}#k=${toB64Url(fileKeyRaw)}`;
        result.textContent = `共有リンク: ${full}`;
        try {
          await navigator.clipboard.writeText(full);
          result.textContent += "(コピーしました)";
        } catch {
          /* クリップボード不可の環境では表示のみ */
        }
      }
      await refreshShares();
    });
  const closeBtn = el("button", { type: "button" }, "閉じる");
  closeBtn.onclick = () => closeDialog(dialog);

  dialog.append(
    el("h2", {}, `「${path}」を共有`),
    el("label", {}, "共有先: ", targetSelect),
    el("label", {}, "有効日数(0 = 無期限): ", expires),
    el("div", { class: "toolbar" }, createBtn, closeBtn),
    result,
  );
  document.body.append(dialog);
  dialog.showModal();
}

async function refreshShares(): Promise<void> {
  const panel = document.getElementById("shares-panel")!;
  const { mine, received } = await api.listShares();

  const receivedBody = el("tbody");
  for (const sh of received) {
    const filename = sh.path.split("/").pop() ?? sh.path;
    const dl = el("button", { class: "link" }, "ダウンロード");
    dl.onclick = () =>
      run(async () => {
        const blob = await api.downloadShared(sh.id);
        const fileKeyRaw = await unwrapKeyFromUser(
          userKeys!.privateKey,
          sh.wrapped_key ?? "",
        );
        saveBytes(await decryptFileWithRawKey(fileKeyRaw, blob), filename);
      });
    receivedBody.append(
      el(
        "tr",
        {},
        el("td", {}, filename),
        el("td", { class: "muted" }, `${sh.owner} さんから`),
        el("td", { class: "muted" }, fmtDate(sh.created_at)),
        el("td", { class: "actions" }, dl),
      ),
    );
  }

  const mineBody = el("tbody");
  for (const sh of mine) {
    const target = sh.target_user ? `${sh.target_user} さんへ` : "リンク共有";
    const cells = el("td", { class: "actions" });
    const del = el("button", { class: "link danger" }, "解除");
    del.onclick = () =>
      run(async () => {
        await api.deleteShare(sh.id);
        await refreshShares();
      });
    cells.append(del);
    mineBody.append(
      el(
        "tr",
        {},
        el("td", {}, sh.path),
        el("td", { class: "muted" }, target),
        el("td", { class: "muted" }, fmtDate(sh.created_at)),
        cells,
      ),
    );
  }

  panel.replaceChildren(
    el("h2", {}, "共有"),
    el("h3", {}, "自分に共有されたファイル"),
    received.length
      ? el(
          "table",
          {},
          el(
            "thead",
            {},
            el(
              "tr",
              {},
              el("th", {}, "ファイル"),
              el("th", {}, "共有元"),
              el("th", {}, "共有日時"),
              el("th", {}, ""),
            ),
          ),
          receivedBody,
        )
      : el("div", { class: "empty" }, "共有されたファイルはありません"),
    el("h3", {}, "自分が共有中のファイル"),
    mine.length
      ? el(
          "table",
          {},
          el(
            "thead",
            {},
            el(
              "tr",
              {},
              el("th", {}, "ファイル"),
              el("th", {}, "共有先"),
              el("th", {}, "共有日時"),
              el("th", {}, ""),
            ),
          ),
          mineBody,
        )
      : el("div", { class: "empty" }, "共有中のファイルはありません"),
    el(
      "div",
      { class: "note" },
      "共有リンクの復号鍵は URL の # 以降に入っており、サーバーには保存されません。" +
        "リンクを共有した時点の URL 全体を相手に渡してください(共有一覧からは再取得できません)。",
    ),
  );
}

// --- メール(件名・本文とも E2E 暗号化) ---

// 一覧表示用: 自分宛に包まれたメール鍵を解いて件名を復号する
async function decryptSubject(m: api.MailMessage): Promise<string> {
  try {
    const mailKey = await unwrapKeyFromUser(userKeys!.privateKey, m.wrapped_key);
    return new TextDecoder().decode(
      await decryptBytesWithRawKey(mailKey, m.enc_subject),
    );
  } catch {
    return "(復号できません)";
  }
}

async function refreshMail(): Promise<void> {
  const panel = document.getElementById("mail-panel")!;
  const [inbox, sent] = await Promise.all([
    api.listMail("inbox"),
    api.listMail("sent"),
  ]);

  const composeBtn = el("button", { class: "primary" }, "新規メール");
  composeBtn.onclick = () => run(() => openComposeDialog());
  const refreshBtn = el("button", {}, "更新");
  refreshBtn.onclick = () => run(refreshMail);

  const makeTable = async (
    msgs: api.MailMessage[],
    who: (m: api.MailMessage) => string,
  ) => {
    const tbody = el("tbody");
    for (const m of msgs) {
      const subject = await decryptSubject(m);
      const subjectCell = el("td", { class: "name-cell" }, subject || "(件名なし)");
      subjectCell.onclick = () => run(() => openMailView(m.id));
      const del = el("button", { class: "link danger" }, "削除");
      del.onclick = () => {
        if (!confirm(`「${subject}」を削除しますか?`)) return;
        run(async () => {
          await api.deleteMail(m.id);
          await refreshMail();
        });
      };
      tbody.append(
        el(
          "tr",
          {},
          subjectCell,
          el("td", { class: "muted" }, who(m)),
          el("td", { class: "muted" }, fmtDate(m.created_at)),
          el("td", { class: "actions" }, del),
        ),
      );
    }
    return el(
      "table",
      {},
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          el("th", {}, "件名"),
          el("th", {}, ""),
          el("th", {}, "日時"),
          el("th", {}, ""),
        ),
      ),
      tbody,
    );
  };

  panel.replaceChildren(
    el("h2", {}, "メール"),
    el("div", { class: "toolbar" }, composeBtn, refreshBtn),
    el("h3", {}, "受信箱"),
    inbox.length
      ? await makeTable(inbox, (m) => `${m.from} さんから`)
      : el("div", { class: "empty" }, "受信メールはありません"),
    el("h3", {}, "送信済み"),
    sent.length
      ? await makeTable(sent, (m) => `${m.to} さんへ`)
      : el("div", { class: "empty" }, "送信済みメールはありません"),
    el(
      "div",
      { class: "note" },
      "メールは件名・本文ともブラウザ内で暗号化され、宛先の人だけが読めます。" +
        "メールも保存容量(ファイルと合わせて 10GB)に含まれます。",
    ),
  );
}

async function openComposeDialog(
  prefTo = "",
  prefSubject = "",
): Promise<void> {
  const dialog = el("dialog");
  // 宛先は普通のテキスト入力(datalist で登録ユーザーの補完だけ出す)
  const toInput = el("input", {
    type: "text",
    placeholder: "宛先ユーザー名",
    list: "mail-user-suggest",
    autocomplete: "off",
  });
  toInput.value = prefTo;
  const suggest = el("datalist", { id: "mail-user-suggest" });
  api
    .listUsers()
    .then((users) => {
      for (const u of users.filter((u) => u !== currentUser)) {
        suggest.append(el("option", { value: u }));
      }
    })
    .catch(() => {
      /* 補完が出ないだけ */
    });
  const subject = el("input", { type: "text", placeholder: "件名" });
  subject.value = prefSubject;
  const body = el("textarea", { rows: "10", placeholder: "本文" });
  const msg = el("div", { class: "note" });

  const sendBtn = el("button", { class: "primary", type: "button" }, "送信");
  sendBtn.onclick = async () => {
    const to = toInput.value.trim();
    if (!to) {
      msg.textContent = "宛先ユーザー名を入力してください";
      return;
    }
    sendBtn.disabled = true;
    msg.textContent = "暗号化して送信しています…";
    try {
      const te = new TextEncoder();
      const mailKey = newRawKey();
      const [encSubject, encBody, toPub] = await Promise.all([
        encryptBytesWithRawKey(mailKey, te.encode(subject.value)),
        encryptBytesWithRawKey(mailKey, te.encode(body.value)),
        api.getUserPublicKey(to),
      ]);
      await api.sendMail({
        to,
        enc_subject: encSubject,
        enc_body: encBody,
        // 宛先が読めるように相手の公開鍵で、自分も送信済みを読めるように自分の公開鍵で包む
        wrapped_key_to: await wrapKeyForUser(mailKey, toPub),
        wrapped_key_self: await wrapKeyForUser(mailKey, userKeys!.publicKeySpki),
      });
      closeDialog(dialog);
      await refreshMail();
    } catch (e) {
      msg.textContent = e instanceof Error ? e.message : String(e);
      sendBtn.disabled = false;
    }
  };
  const closeBtn = el("button", { type: "button" }, "閉じる");
  closeBtn.onclick = () => closeDialog(dialog);

  dialog.append(
    el("h2", {}, "新規メール"),
    toInput,
    suggest,
    subject,
    body,
    el("div", { class: "toolbar" }, sendBtn, closeBtn),
    msg,
  );
  document.body.append(dialog);
  dialog.showModal();
}

async function openMailView(id: string): Promise<void> {
  const m = await api.getMail(id);
  const mailKey = await unwrapKeyFromUser(userKeys!.privateKey, m.wrapped_key);
  const td = new TextDecoder();
  const subject = td.decode(await decryptBytesWithRawKey(mailKey, m.enc_subject));
  const body = td.decode(await decryptBytesWithRawKey(mailKey, m.enc_body ?? ""));

  const dialog = el("dialog", { class: "wide" });
  const pre = el("pre", { class: "mail-body" }, body);

  const buttons = el("div", { class: "toolbar" });
  if (m.folder === "inbox") {
    const replyBtn = el("button", { type: "button" }, "返信");
    replyBtn.onclick = () => {
      closeDialog(dialog);
      run(() =>
        openComposeDialog(
          m.from,
          subject.startsWith("Re:") ? subject : `Re: ${subject}`,
        ),
      );
    };
    buttons.append(replyBtn);
  }
  const closeBtn = el("button", { type: "button" }, "閉じる");
  closeBtn.onclick = () => closeDialog(dialog);
  buttons.append(closeBtn);

  dialog.append(
    el("h2", {}, subject || "(件名なし)"),
    el(
      "div",
      { class: "note" },
      `${m.from} さんから ${m.to} さんへ · ${fmtDate(m.created_at)}`,
    ),
    pre,
    buttons,
  );
  document.body.append(dialog);
  dialog.showModal();
}

// --- パスワード変更(マスター鍵は変わらないので既存ファイルはそのまま読める) ---

function openPasswordDialog(): void {
  const dialog = el("dialog");
  const current = el("input", {
    type: "password",
    placeholder: "現在のパスワード",
    autocomplete: "current-password",
  });
  const next = el("input", {
    type: "password",
    placeholder: "新しいパスワード(8 文字以上)",
    autocomplete: "new-password",
  });
  const next2 = el("input", {
    type: "password",
    placeholder: "新しいパスワード(確認)",
    autocomplete: "new-password",
  });
  const msg = el("div", { class: "note" });
  const okBtn = el("button", { class: "primary", type: "button" }, "変更する");
  okBtn.onclick = async () => {
    if (next.value.length < 8) {
      msg.textContent = "新しいパスワードは 8 文字以上にしてください";
      return;
    }
    if (next.value !== next2.value) {
      msg.textContent = "新しいパスワードが一致しません";
      return;
    }
    okBtn.disabled = true;
    msg.textContent = "鍵を包み直しています…";
    try {
      const oldKeys = await deriveKeys(currentUser, current.value);
      const bundle = await api.getKeyBundle();
      if (!bundle) throw new Error("鍵バンドルが見つかりません");
      const newKeys = await deriveKeys(currentUser, next.value);
      // 現在のパスワードが違えばここで復号に失敗する
      const newBundle = await rewrapKeyBundle(
        oldKeys.wrapKey,
        newKeys.wrapKey,
        bundle,
      );
      await api.changePassword(newKeys.authKey, newBundle);
      msg.textContent = "パスワードを変更しました";
      setTimeout(() => closeDialog(dialog), 1200);
    } catch (e) {
      msg.textContent =
        e instanceof Error && e.name === "OperationError"
          ? "現在のパスワードが違います"
          : e instanceof Error
            ? e.message
            : String(e);
    } finally {
      okBtn.disabled = false;
    }
  };
  const closeBtn = el("button", { type: "button" }, "閉じる");
  closeBtn.onclick = () => closeDialog(dialog);

  dialog.append(
    el("h2", {}, "パスワード変更"),
    current,
    next,
    next2,
    el("div", { class: "toolbar" }, okBtn, closeBtn),
    msg,
  );
  document.body.append(dialog);
  dialog.showModal();
}

// --- 共有リンクの閲覧ページ (/s/<token>#k=<鍵>) ---

function renderShareViewer(token: string): void {
  const keyParam = new URLSearchParams(location.hash.slice(1)).get("k");
  const status = el("div", { class: "note" });
  const dlBtn = el(
    "button",
    { class: "primary", type: "button" },
    "ダウンロード",
  );
  dlBtn.disabled = !keyParam;
  if (!keyParam) {
    status.textContent =
      "URL に復号鍵(# 以降の部分)がありません。リンク全体をコピーしたか確認してください。";
  }
  dlBtn.onclick = async () => {
    dlBtn.disabled = true;
    status.textContent = "取得して復号しています…";
    try {
      const { data, filename } = await api.downloadPublicShare(token);
      const decrypted = await decryptFileWithRawKey(fromB64Url(keyParam!), data);
      saveBytes(decrypted, filename);
      status.textContent = `「${filename}」を保存しました`;
    } catch (e) {
      status.textContent = e instanceof Error ? e.message : String(e);
    } finally {
      dlBtn.disabled = false;
    }
  };

  app.replaceChildren(
    el(
      "div",
      { class: "login-wrap" },
      el(
        "div",
        { class: "login-card" },
        el("h1", {}, "共有ファイル"),
        el(
          "div",
          { class: "note" },
          "ファイルはブラウザ内で復号されます。復号鍵はサーバーに送信されません。",
        ),
        dlBtn,
        status,
      ),
    ),
  );
}

// --- 起動 ---

async function start(): Promise<void> {
  const shareMatch = /^\/s\/([A-Za-z0-9_-]+)$/.exec(location.pathname);
  if (shareMatch) {
    renderShareViewer(shareMatch[1]);
    return;
  }
  const session = api.savedSession();
  if (session) {
    const keys = await loadKeys(session.username);
    if (keys) {
      api.setToken(session.token);
      currentUser = session.username;
      userKeys = keys;
      await renderMain();
      return;
    }
    // トークンはあるが鍵が無い(別ブラウザ等) → 再ログインで鍵を導出してもらう
    api.clearSession();
    renderLogin("暗号鍵を再導出するため、もう一度ログインしてください。");
    return;
  }
  renderLogin();
}

start();
