/// <reference types="@sveltejs/kit" />
// @ts-nocheck
import { build, files, version } from '$service-worker';

const CACHE = `cache-${version}`;
const ASSETS = [...build, ...files];

self.addEventListener('install', (event) => {
    async function addFilesToCache() {
        const cache = await caches.open(CACHE);
        await cache.addAll(ASSETS);
    }
    event.waitUntil(addFilesToCache());
});

self.addEventListener('activate', (event) => {
    async function deleteOldCaches() {
        for (const key of await caches.keys()) {
            if (key !== CACHE) await caches.delete(key);
        }
    }
    event.waitUntil(deleteOldCaches());
});

self.addEventListener('fetch', (event) => {
    if (event.request.method !== 'GET') return;

    async function respond() {
        const url = new URL(event.request.url);
        const cache = await caches.open(CACHE);
        const isNavigationRequest = event.request.mode === 'navigate';

        // Serve cached assets
        if (ASSETS.includes(url.pathname)) {
            return cache.match(event.request); // Corrected line
        }

        try {
            const response = await fetch(event.request);
            if (response.status === 200) {
                cache.put(event.request, response.clone());
            }
            return response;
        } catch (err) {
            // If navigation request and offline, serve index.html
            if (isNavigationRequest) {
                const cached = await cache.match('/index.html');
                if (cached) return cached;
            }
            // Otherwise, return cached asset if available
            return cache.match(event.request);
        }
    }

    event.respondWith(respond());
});
