/* IoTSentinel service worker.
 *
 * Served from the site root (/sw.js) so its scope is the whole app, not /assets/.
 *
 * SAFETY MODEL — this app is authenticated (Flask-Login), dynamic (Dash callbacks),
 * and real-time (Socket.IO). The worker must never serve stale or wrong security
 * data, and must never interfere with auth. So:
 *   - non-GET requests are not intercepted at all  -> every login/CSRF/Dash POST
 *     reaches the server untouched.
 *   - navigations and all auth/api/live endpoints are network-only.
 *   - ONLY immutable, content-addressed static assets are cached.
 * Bump CACHE on any change to this logic to evict the old cache.
 */
const CACHE = 'iotsentinel-static-v1';
const OFFLINE_URL = '/assets/offline.html';
const MAX_ENTRIES = 120;   // cap the static cache so it can't grow without bound

// Evict oldest entries (FIFO) once the cache exceeds MAX_ENTRIES.
function trimCache(cacheName, max) {
  caches.open(cacheName).then((cache) =>
    cache.keys().then((keys) => {
      if (keys.length <= max) return;
      cache.delete(keys[0]).then(() => trimCache(cacheName, max));
    })
  ).catch(() => {});
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.add(OFFLINE_URL)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Paths that must always hit the network (auth, live data, dynamic callbacks).
const NETWORK_ONLY_PREFIXES = [
  '/_dash-update-component',
  '/api/',
  '/auth/',
  '/health',
  '/download-report',
  '/login',
  '/logout',
  '/socket.io/',
  '/ws',
];

// Immutable static assets that are safe to cache-first (filenames are stable or
// content-hashed by Dash, so a cached copy can never be wrong for a release).
function isCacheableStatic(url) {
  const p = url.pathname;
  if (p.startsWith('/_dash-component-suites/')) return true;  // hashed bundles
  if (p === '/_favicon.ico') return true;
  if (p.startsWith('/assets/')) {
    return /\.(min\.css|css|woff2|woff|png|svg|ico|js|webmanifest)$/.test(p);
  }
  return false;
}

self.addEventListener('fetch', (event) => {
  const req = event.request;

  // 1. Never touch non-GET — login forms, Dash callbacks, WebAuthn all POST.
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Only handle same-origin requests; let cross-origin (CDNs, APIs) pass through.
  if (url.origin !== self.location.origin) return;

  // 2. Navigations: network-only, with an offline shell fallback when truly down.
  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).catch(() => caches.match(OFFLINE_URL)));
    return;
  }

  // 3. Auth / live / dynamic endpoints: network-only, never cached.
  if (NETWORK_ONLY_PREFIXES.some((prefix) => url.pathname.startsWith(prefix))) {
    event.respondWith(fetch(req));
    return;
  }

  // 4. Immutable statics: cache-first, populate on miss.
  if (isCacheableStatic(url)) {
    event.respondWith(
      caches.match(req).then((hit) => {
        if (hit) return hit;
        return fetch(req).then((res) => {
          if (res && res.ok && res.status === 200 && res.type === 'basic') {
            const copy = res.clone();
            caches.open(CACHE).then((cache) => {
              cache.put(req, copy);
              trimCache(CACHE, MAX_ENTRIES);
            }).catch(() => {});
          }
          return res;
        });
      })
    );
    return;
  }

  // 5. Everything else: plain network, no caching.
});
