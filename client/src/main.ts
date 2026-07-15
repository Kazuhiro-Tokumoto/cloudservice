// クラウドサービス Web クライアント本体。
// ログイン → ファイル一覧・アップロード・ダウンロード・削除・共有 を提供する。
import * as api from "./api";
import { deriveAuthKey } from "./crypto";

const app = document.getElementById("app")!;

let currentUser = "";
let currentPath = "";

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

function fmtSize(n: number): string {
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

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString("ja-JP");
}

function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
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

async function run(action: () => Promise<void>): Promise<void> {
  try {
    await action();
  } catch (e) {
    showError(e instanceof Error ? e.message : String(e));
    // 認証切れならログイン画面へ
    if (!api.savedSession() && currentUser) {
      currentUser = "";
      renderLogin();
    }
  }
}

// --- ログイン画面 ---

function renderLogin(): void {
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
  const msg = el("div", { class: "note", id: "login-msg" });
  const btn = el("button", { class: "primary", type: "submit" }, "ログイン");

  const form = el("form", {}, username, password, btn, msg);
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    msg.textContent = "認証キーを計算中…";
    try {
      // パスワードは送らず、SHA-256 で導出した認証キーを秘密鍵として送信
      const key = await deriveAuthKey(username.value, password.value);
      currentUser = await api.login(username.value, key);
      currentPath = "";
      await renderMain();
    } catch (e) {
      msg.textContent = e instanceof Error ? e.message : String(e);
    }
  };

  app.replaceChildren(
    el(
      "div",
      { class: "login-wrap" },
      el(
        "div",
        { class: "login-card" },
        el("h1", {}, "☁ クラウドサービス"),
        form,
        el(
          "div",
          { class: "note" },
          "パスワードはブラウザ内でハッシュ化され、そのまま送信されることはありません。アカウントは管理者に発行してもらってください。",
        ),
      ),
    ),
  );
}

// --- メイン画面 ---

async function renderMain(): Promise<void> {
  const errorBanner = el("div", {
    class: "error-banner",
    id: "error-banner",
  });
  errorBanner.hidden = true;

  const logoutBtn = el("button", {}, "ログアウト");
  logoutBtn.onclick = () => {
    api.clearSession();
    api.setToken("");
    currentUser = "";
    renderLogin();
  };

  const filesSection = el("section", { class: "panel", id: "files-panel" });
  const sharesSection = el("section", { class: "panel", id: "shares-panel" });

  app.replaceChildren(
    el(
      "header",
      { class: "topbar" },
      el("h1", {}, "☁ クラウドサービス"),
      el("div", { class: "userbox" }, `${currentUser} さん`, logoutBtn),
    ),
    el("main", {}, errorBanner, filesSection, sharesSection),
  );

  await run(refreshFiles);
  await run(refreshShares);
}

async function refreshFiles(): Promise<void> {
  const panel = document.getElementById("files-panel")!;
  const entries = await api.listFiles(currentPath);

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
        await api.uploadFile(dest, f);
      }
      fileInput.value = "";
      await refreshFiles();
    });
  const uploadBtn = el("button", { class: "primary" }, "⬆ アップロード");
  uploadBtn.onclick = () => fileInput.click();

  const mkdirBtn = el("button", {}, "📁 フォルダ作成");
  mkdirBtn.onclick = () => {
    const name = prompt("フォルダ名を入力してください");
    if (!name) return;
    run(async () => {
      await api.mkdir(currentPath ? `${currentPath}/${name}` : name);
      await refreshFiles();
    });
  };

  const newFileBtn = el("button", {}, "📝 テキスト作成");
  newFileBtn.onclick = () => {
    const name = prompt("ファイル名を入力してください", "memo.txt");
    if (!name) return;
    run(async () => {
      const dest = currentPath ? `${currentPath}/${name}` : name;
      await api.uploadFile(dest, new Blob([""]));
      await refreshFiles();
      await openEditor(dest);
    });
  };

  const refreshBtn = el("button", {}, "↻ 更新");
  refreshBtn.onclick = () => run(refreshFiles);

  // ファイル一覧テーブル
  const tbody = el("tbody");
  for (const entry of entries) {
    const nameCell = el(
      "td",
      { class: entry.is_dir ? "name-cell" : "name-cell" },
      (entry.is_dir ? "📁 " : "📄 ") + entry.name,
    );
    nameCell.onclick = () => {
      if (entry.is_dir) {
        currentPath = entry.path;
        run(refreshFiles);
      } else if (isTextFile(entry.name) && entry.size < 1024 * 1024) {
        run(() => openEditor(entry.path));
      } else {
        run(async () => saveBlob(await api.downloadFile(entry.path), entry.name));
      }
    };

    const actions = el("td", { class: "actions" });
    if (!entry.is_dir) {
      const dl = el("button", { class: "link", title: "ダウンロード" }, "⬇");
      dl.onclick = () =>
        run(async () => saveBlob(await api.downloadFile(entry.path), entry.name));
      const share = el("button", { class: "link", title: "共有" }, "🔗");
      share.onclick = () => openShareDialog(entry.path);
      actions.append(dl, share);
    }
    const del = el("button", { class: "link danger", title: "削除" }, "🗑");
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
        nameCell,
        el("td", {}, entry.is_dir ? "—" : fmtSize(entry.size)),
        el("td", {}, fmtDate(entry.mod_time)),
        actions,
      ),
    );
  }

  const table = el(
    "table",
    {},
    el(
      "thead",
      {},
      el(
        "tr",
        {},
        el("th", {}, "名前"),
        el("th", {}, "サイズ"),
        el("th", {}, "更新日時"),
        el("th", {}, ""),
      ),
    ),
    tbody,
  );

  panel.replaceChildren(
    el("h2", {}, "マイファイル"),
    el(
      "div",
      { class: "toolbar" },
      uploadBtn,
      mkdirBtn,
      newFileBtn,
      refreshBtn,
      fileInput,
    ),
    crumbs,
    entries.length ? table : el("div", { class: "empty" }, "ファイルはありません"),
  );
}

function isTextFile(name: string): boolean {
  return /\.(txt|md|json|csv|log|yaml|yml|xml|html|css|js|ts|go|py|sh|conf|ini)$/i.test(
    name,
  );
}

// --- テキストエディタ(ファイルの読み出し・書き込み) ---

async function openEditor(path: string): Promise<void> {
  const content = await api.readTextFile(path);
  const dialog = el("dialog");
  const textarea = el("textarea", { rows: "16" }) as HTMLTextAreaElement;
  textarea.style.width = "100%";
  textarea.style.fontFamily = "monospace";
  textarea.value = content;

  const saveBtn = el("button", { class: "primary", type: "button" }, "保存");
  saveBtn.onclick = () =>
    run(async () => {
      await api.uploadFile(path, new Blob([textarea.value]));
      dialog.close();
      dialog.remove();
      await refreshFiles();
    });
  const closeBtn = el("button", { type: "button" }, "閉じる");
  closeBtn.onclick = () => {
    dialog.close();
    dialog.remove();
  };

  dialog.append(
    el("h2", {}, path),
    textarea,
    el("div", { class: "toolbar" }, saveBtn, closeBtn),
  );
  dialog.style.width = "640px";
  document.body.append(dialog);
  dialog.showModal();
}

// --- 共有 ---

async function openShareDialog(path: string): Promise<void> {
  const users = (await api.listUsers()).filter((u) => u !== currentUser);

  const dialog = el("dialog");
  const targetSelect = el("select");
  targetSelect.append(el("option", { value: "" }, "リンク共有(URL を知っていれば誰でも)"));
  for (const u of users) {
    targetSelect.append(el("option", { value: u }, `ユーザー: ${u}`));
  }
  const expires = el("input", {
    type: "number",
    min: "0",
    value: "0",
    title: "有効日数(0 = 無期限)",
  });
  const result = el("div", { class: "share-url" });

  const createBtn = el("button", { class: "primary", type: "button" }, "共有を作成");
  createBtn.onclick = () =>
    run(async () => {
      const res = await api.createShare(
        path,
        targetSelect.value,
        Number(expires.value) || 0,
      );
      if (res.url) {
        const full = `${location.origin}${res.url}`;
        result.textContent = `共有リンク: ${full}`;
        try {
          await navigator.clipboard.writeText(full);
          result.textContent += "(コピーしました)";
        } catch {
          /* クリップボード不可の環境では表示のみ */
        }
      } else {
        result.textContent = `${targetSelect.value} さんに共有しました`;
      }
      await refreshShares();
    });
  const closeBtn = el("button", { type: "button" }, "閉じる");
  closeBtn.onclick = () => {
    dialog.close();
    dialog.remove();
  };

  dialog.append(
    el("h2", {}, `「${path}」を共有`),
    el("div", {}, "共有先: ", targetSelect),
    el("div", {}, "有効日数(0 = 無期限): ", expires),
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
    const dl = el("button", { class: "link" }, "⬇ ダウンロード");
    const filename = sh.path.split("/").pop() ?? sh.path;
    dl.onclick = () =>
      run(async () => saveBlob(await api.downloadShared(sh.id), filename));
    receivedBody.append(
      el(
        "tr",
        {},
        el("td", {}, `📄 ${filename}`),
        el("td", {}, `${sh.owner} さんから`),
        el("td", {}, fmtDate(sh.created_at)),
        el("td", { class: "actions" }, dl),
      ),
    );
  }

  const mineBody = el("tbody");
  for (const sh of mine) {
    const target = sh.target_user
      ? `${sh.target_user} さんへ`
      : "リンク共有";
    const cells = el("td", { class: "actions" });
    if (!sh.target_user) {
      const copy = el("button", { class: "link" }, "URL コピー");
      copy.onclick = async () => {
        const full = `${location.origin}/s/${sh.id}`;
        try {
          await navigator.clipboard.writeText(full);
          copy.textContent = "コピーしました";
        } catch {
          prompt("共有 URL:", full);
        }
      };
      cells.append(copy);
    }
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
        el("td", {}, `📄 ${sh.path}`),
        el("td", {}, target),
        el("td", {}, fmtDate(sh.created_at)),
        cells,
      ),
    );
  }

  panel.replaceChildren(
    el("h2", {}, "共有"),
    el("h2", {}, "自分に共有されたファイル"),
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
    el("h2", {}, "自分が共有中のファイル"),
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
  );
}

// --- 起動 ---

const session = api.savedSession();
if (session) {
  api.setToken(session.token);
  currentUser = session.username;
  renderMain();
} else {
  renderLogin();
}
