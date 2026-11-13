const CACHE_NAME = 'qr-medcheck-shell-v1';
const APP_SHELL = [
    './',
    './manifest.webmanifest',
    './app-icon.svg',
    './qr-medcheck-logo.png'
];

self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(APP_SHELL))
            .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys()
            .then(cacheNames => Promise.all(
                cacheNames
                    .filter(cacheName => cacheName.startsWith('qr-medcheck-shell-') && cacheName !== CACHE_NAME)
                    .map(cacheName => caches.delete(cacheName))
            ))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', event => {
    const request = event.request;
    const requestUrl = new URL(request.url);

    if (request.method !== 'GET' || requestUrl.origin !== self.location.origin) return;
    if (requestUrl.pathname.includes('/api/')) {
        event.respondWith(fetch(request));
        return;
    }

    if (request.mode === 'navigate') {
        event.respondWith(
            fetch(request)
                .then(async response => {
                    if (response.ok) {
                        const shellUrl = new URL('./', self.registration.scope);
                        try {
                            const cache = await caches.open(CACHE_NAME);
                            await cache.put(shellUrl, response.clone());
                        } catch (error) {
                            console.error('Could not cache the QR MedCheck app shell:', error);
                        }
                    }
                    return response;
                })
                .catch(async () => {
                    const shellUrl = new URL('./', self.registration.scope);
                    const cachedShell = await caches.match(shellUrl);
                    if (cachedShell) return cachedShell;
                    return Response.error();
                })
        );
        return;
    }

    event.respondWith(
        fetch(request)
            .then(async response => {
                if (response.ok) {
                    try {
                        const cache = await caches.open(CACHE_NAME);
                        await cache.put(request, response.clone());
                    } catch (error) {
                        console.error('Could not cache a QR MedCheck app resource:', error);
                    }
                }
                return response;
            })
            .catch(async () => (await caches.match(request)) || Response.error())
    );
});
