'use strict';
/*
 * Mac Touchpad service worker (HTTPS only).
 *
 * Stale-while-revalidate for the app shell: answer from cache immediately so the
 * Home Screen icon opens even when the Mac is off, and refresh the cache in the
 * background when the Mac is reachable.
 *
 * Updates: when a background refresh brings a different file (new ETag), the
 * page is told ("updated") and reloads itself as soon as you're not touching it.
 * The page also asks for a check ("check") every time it reconnects, because iOS
 * keeps Home Screen apps alive for days without reloading them.
 * The WebSocket never goes through here.
 */
const CACHE = 'mtp-shell-v2';
const SHELL = ['./', 'style.css', 'app.js', 'hmac.js', 'manifest.webmanifest',
               'icon-180.png', 'icon-192.png', 'icon-512.png'];

const scopeUrl = (p) => new URL(p, self.registration.scope).href;

async function notifyUpdated() {
  for (const c of await self.clients.matchAll({ type: 'window' })) c.postMessage({ t: 'updated' });
}

// Did a fresh response change compared with what we had cached?
const differs = (fresh, cached) => {
  if (!cached) return false;
  const a = fresh.headers.get('ETag'), b = cached.headers.get('ETag');
  if (a || b) return a !== b;
  return fresh.headers.get('Last-Modified') !== cached.headers.get('Last-Modified');
};

async function checkForUpdate() {
  const cache = await caches.open(CACHE);
  let changed = false;
  await Promise.all(SHELL.map(async (p) => {
    const url = scopeUrl(p);
    try {
      const res = await fetch(url, { cache: 'no-cache' });
      if (!res.ok) return;
      const old = await cache.match(url, { ignoreSearch: true });
      if (!old || differs(res, old)) {
        if (old) changed = true;
        await cache.put(url, res);
      }
    } catch (_) { /* Mac unreachable: keep what we have */ }
  }));
  if (changed) await notifyUpdated();
}

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE)
    .then((c) => c.addAll(SHELL.map((p) => new Request(scopeUrl(p), { cache: 'no-cache' }))))
    .then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const stale = (await caches.keys()).filter((k) => k !== CACHE);
    await Promise.all(stale.map((k) => caches.delete(k)));
    await self.clients.claim();
    // Upgrading from an older version: the open page is running old code, reload it now.
    if (stale.length) {
      for (const c of await self.clients.matchAll({ type: 'window' })) c.navigate(c.url).catch(() => {});
    }
  })());
});

self.addEventListener('message', (e) => {
  if (e.data && e.data.t === 'check') e.waitUntil(checkForUpdate());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== location.origin || !url.pathname.startsWith(new URL(self.registration.scope).pathname)
      || url.pathname.endsWith('/ws')) return;
  // Navigations to the app (with or without query) map to the cached index.
  const key = req.mode === 'navigate' ? scopeUrl('./') : req;
  e.respondWith(caches.open(CACHE).then(async (cache) => {
    const cached = await cache.match(key, { ignoreSearch: true });
    // (The server sends Cache-Control: no-cache, so this always revalidates.)
    const fresh = fetch(req).then(async (res) => {
      if (res.ok) {
        const changed = differs(res, cached);
        await cache.put(key, res.clone());
        if (changed) notifyUpdated();
      }
      return res;
    });
    if (cached) { e.waitUntil(fresh.catch(() => {})); return cached; }
    return fresh;
  }));
});
