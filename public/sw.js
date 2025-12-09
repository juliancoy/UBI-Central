const CACHE_NAME = 'ubi-central-pwa-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/styles.css',
  '/nav.js',
  '/app.js',
  '/account.html',
  '/account.js',
  '/admin.html',
  '/admin.js',
  '/bio.html',
  '/bio.js',
  '/invoice.html',
  '/invoice.js',
  '/pay.html',
  '/pay.js',
  '/privacy.html',
  '/qrcode.min.js',
  '/manifest.webmanifest',
  '/icons/icon.svg',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;

  const handle = async () => {
    const cached = await caches.match(request);
    if (cached) return cached;
    try {
      const network = await fetch(request);
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, network.clone());
      return network;
    } catch (err) {
      if (request.mode === 'navigate') {
        const fallback = await caches.match('/index.html');
        if (fallback) return fallback;
      }
      throw err;
    }
  };

  event.respondWith(handle());
});
