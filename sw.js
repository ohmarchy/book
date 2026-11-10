// Service worker of the encrypted book (scheme in encrypt.mjs).
// It holds no secret: the root key comes from IndexedDB, where the unlock page
// stored it after deriving it from the password. With a wrong password every
// file decrypts to noise, and the noise is what the browser gets.
const P = {"v":1,"salt":"140f16a36b62a48473d7caf8868ef81a","iter":1200000,"base":"/book/"};
const enc = new TextEncoder();
const unhex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));
const SALT = unhex(P.salt);
const TYPES = {
  html: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8', json: 'application/json', svg: 'image/svg+xml', png: 'image/png',
  jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', ico: 'image/x-icon',
  woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', otf: 'font/otf', txt: 'text/plain; charset=utf-8',
  md: 'text/plain; charset=utf-8', map: 'application/json', xml: 'application/xml',
};

function db() {
  return new Promise((ok, no) => {
    const r = indexedDB.open('ohmarchy-book', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('k');
    r.onsuccess = () => ok(r.result);
    r.onerror = () => no(r.error);
  });
}
async function idb(mode, fn) {
  const d = await db();
  return new Promise((ok, no) => {
    const t = d.transaction('k', mode);
    const q = fn(t.objectStore('k'));
    t.oncomplete = () => ok(q && q.result);
    t.onerror = () => no(t.error);
  });
}
let cached = null;
async function rootKey() {
  if (!cached) {
    const v = await idb('readonly', (s) => s.get('root'));
    if (v && v.salt === P.salt) cached = v.key;
  }
  return cached;
}

async function blobName(rel) {
  const parts = [enc.encode('ohmarchy-book/v1/name'), SALT, enc.encode(rel)];
  const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { buf.set(p, o); o += p.length; }
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('').slice(0, 40);
}

async function open(root, blob) {
  const nonce = blob.slice(0, 16);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: nonce, info: enc.encode('ohmarchy-book/v1/aes-ctr') },
    root, { name: 'AES-CTR', length: 256 }, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-CTR', counter: new Uint8Array(16), length: 64 }, key, blob.slice(16));
  try {
    return await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
  } catch {
    return plain; // wrong password: hand over the noise as it is
  }
}

async function fetchBlob(scope, rel) {
  const r = await fetch(scope + 'c/' + (await blobName(rel)));
  return r.ok ? new Uint8Array(await r.arrayBuffer()) : null;
}

async function serve(request, scope, rel) {
  const root = await rootKey();
  if (!root) return fetch(request);
  let name = rel, blob = await fetchBlob(scope, name);
  if (!blob && !/\.[a-z0-9]+$/i.test(name)) {
    for (const alt of [name + '.html', name + '/index.html']) {
      if ((blob = await fetchBlob(scope, alt))) { name = alt; break; }
    }
  }
  let status = 200;
  if (!blob) { name = '404.html'; status = 404; blob = await fetchBlob(scope, name); }
  if (!blob) return new Response('not found', { status: 404 });
  const ext = (name.match(/\.([a-z0-9]+)$/i) || [, ''])[1].toLowerCase();
  return new Response(await open(root, blob), {
    status, headers: { 'Content-Type': TYPES[ext] || 'application/octet-stream', 'Cache-Control': 'no-store' },
  });
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  const scope = self.registration.scope;
  if (e.request.method !== 'GET' || !url.href.startsWith(scope)) return;
  let rel = decodeURIComponent(url.pathname.slice(new URL(scope).pathname.length));
  if (rel === 'sw.js' || rel.startsWith('c/')) return;
  if (rel === '__lock') {
    e.respondWith(idb('readwrite', (s) => s.delete('root')).then(() => { cached = null; return Response.redirect(scope, 302); }));
    return;
  }
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  e.respondWith(serve(e.request, scope, rel));
});
