// プッシュ通知用 Service Worker。
// 通知の中身(メール本文など)はサーバーが持っていないため、定型文のみ表示される。
self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    /* 形式が違っても既定文言で表示する */
  }
  event.waitUntil(
    self.registration.showNotification(data.title || "クラウドサービス", {
      body: data.body || "新しいお知らせがあります",
      tag: "cloudservice",
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if ("focus" in c) return c.focus();
      }
      return clients.openWindow("/");
    }),
  );
});
