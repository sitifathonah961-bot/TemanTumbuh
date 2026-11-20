const CACHE_NAME = "teman-tumbuh-v19-admin-management";
const APP_SHELL = [
  "./",
  "./index.html",
  "./manifest.json",
  "./icon-192.png",
  "./icon-512.png"
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") return;

  event.respondWith((async () => {
    const isAppDocument = event.request.mode === "navigate" ||
      new URL(event.request.url).pathname.endsWith("/index.html");
    if (isAppDocument) {
      try {
        const fresh = await fetch(event.request, { cache: "no-store" });
        if (fresh && fresh.ok) {
          const cache = await caches.open(CACHE_NAME);
          await cache.put(event.request, fresh.clone());
        }
        return fresh;
      } catch (error) {
        return (await caches.match(event.request)) || (await caches.match("./index.html"));
      }
    }
    const cached = await caches.match(event.request);
    if (cached) return cached;
    try {
      const response = await fetch(event.request);
      if (response && response.ok) {
        const cache = await caches.open(CACHE_NAME);
        await cache.put(event.request, response.clone());
      }
      return response;
    } catch (error) {
      return caches.match("./index.html");
    }
  })());
});
