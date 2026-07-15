import { defineConfig } from "vite";

// 開発時は vite dev サーバーから Go サーバーへ API をプロキシする。
// 環境変数 API_TARGET でプロキシ先を変更できる(デフォルトはローカルの HTTP 起動)。
const target = process.env.API_TARGET ?? "http://localhost:8443";

export default defineConfig({
  server: {
    proxy: {
      "/api": { target, secure: false },
      "/s": { target, secure: false },
    },
  },
  build: {
    outDir: "dist",
  },
});
