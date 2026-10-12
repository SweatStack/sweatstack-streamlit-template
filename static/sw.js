/*
 * Service worker, registered by proxy.py on every page when manifest.json exists.
 *
 * Why it exists: Chrome only fires `beforeinstallprompt` (which the install
 * banner needs) for sites whose service worker handles `fetch`.
 *
 * What it does: nothing is cached. Every request goes to the network, so a
 * deploy can never be hidden behind a stale cache. Page loads that fail
 * because the device is offline get a small "You're offline" page instead of
 * the browser's error screen.
 */

const OFFLINE_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Offline</title>
<style>
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         font-family: system-ui, sans-serif; text-align: center; color: #31333f; }
  button { font: inherit; padding: 8px 20px; border-radius: 8px;
           border: 1px solid #d0d0d7; background: #fff; cursor: pointer; }
</style>
</head>
<body>
  <main>
    <p>You're offline. Check your connection and try again.</p>
    <button onclick="location.reload()">Try again</button>
  </main>
</body>
</html>`;

self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", (event) => {
  event.waitUntil(
    Promise.all([
      self.clients.claim(),
      // Start page requests while the worker boots, so it adds no latency.
      self.registration.navigationPreload?.enable(),
    ]),
  );
});

self.addEventListener("fetch", (event) => {
  if (event.request.mode !== "navigate") return;
  event.respondWith(
    (async () => {
      try {
        return (await event.preloadResponse) || (await fetch(event.request));
      } catch {
        return new Response(OFFLINE_PAGE, {
          status: 503,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }
    })(),
  );
});
