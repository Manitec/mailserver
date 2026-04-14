const CACHE_VERSION = 'v2';
const CACHE_NAME = `manitec-mail-${CACHE_VERSION}`;
const STATIC_ASSETS = [
  '/',
  '/static/index.html',
  '/static/manifest.json',
  '/static/icons/icon-192x192.png',
  '/static/icons/icon-512x512.png',
  '/offline'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      // addAll fails silently per-item; use individual adds to avoid one bad URL killing all
      return Promise.allSettled(
        STATIC_ASSETS.map(url =>
          cache.add(url).catch(err => console.warn(`[SW] Failed to cache ${url}:`, err))
        )
      );
    })
  );
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    })
  );
  self.clients.claim();
});

// Fetch event - network first, fallback to cache, then offline page
self.addEventListener('fetch', (event) => {
  // Skip non-GET requests
  if (event.request.method !== 'GET') return;

  // Skip API / dynamic routes — let them go straight to network
  const dynamicRoutes = ['/inbox', '/message', '/send', '/reply', '/forward', '/api/'];
  if (dynamicRoutes.some(route => event.request.url.includes(route))) return;

  event.respondWith(
    Promise.race([
      fetch(event.request).then((response) => {
        if (response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 8000))
    ]).catch(() => {
      return caches.match(event.request).then(cached => {
        if (cached) return cached;
        // For navigation requests, serve offline fallback
        if (event.request.mode === 'navigate') {
          return caches.match('/offline') || caches.match('/');
        }
      });
    })
  );
});
