// The proxy engine: sanitize URL -> guard SSRF -> scrub headers -> fetch
// upstream (manual redirects, each hop re-scrubbed) -> filter cookies ->
// rewrite HTML -> deliver.

import { Readable } from 'node:stream';
import { rewriteHtml, injectHud } from './rewrite.js';
import { buildOutboundHeaders } from './headers.js';
import { assertPublicHost } from './ssrf.js';

const GIF_1PX = Buffer.from(
  'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
  'base64'
);

const MAX_HTML_BYTES = 8 * 1024 * 1024;
const MAX_BODY_BYTES = 10 * 1024 * 1024;
const TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 10;

const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function shellPage(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(
    title
  )}</title>
<style>
body{background:#06080c;color:#c8d6e5;font:15px/1.7 ui-sans-serif,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.c{max-width:440px;text-align:center;background:#0c111a;border:1px solid #1c2637;border-radius:16px;padding:36px 32px}
h1{margin:0 0 10px;font-size:21px}p{color:#6b7f99;margin:8px 0 22px;word-break:break-all}
a{color:#5cd6ff;text-decoration:none}
</style></head><body><div class="c">${body}</div></body></html>`;
}

export function createProxyHandler({
  stats,
  blocklist,
  params,
  cookies, // CookieJar
  allowLoopback = false,
  fetchImpl = fetch,
  stealthProfile = null, // entry from config/profiles.json, or null for pass-through
  timeoutMs = TIMEOUT_MS, // per-upstream-request timeout (serverless plans are tighter)
} = {}) {
  const timeout = () => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    return { ctrl, done: () => clearTimeout(t) };
  };

  async function readBody(req) {
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > MAX_BODY_BYTES) throw new Error('request body too large');
      chunks.push(c);
    }
    return Buffer.concat(chunks);
  }

  function sendError(res, code, message) {
    if (res.headersSent) return res.end();
    res.writeHead(code, { 'content-type': 'text/html; charset=utf-8', 'x-veil-error': '1' });
    res.end(
      shellPage(
        `veil — ${code}`,
        `<h1>${esc(message)}</h1>
<p>\u{1F6E1} that's an error from veil, not the site.</p>
<a href="javascript:history.back()">&larr; go back</a> &nbsp;·&nbsp; <a href="/">veil home</a>`
      )
    );
  }

  function sendBlockPage(res, url, reason) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'x-veil-blocked': reason });
    res.end(
      shellPage(
        'veil — blocked',
        `<h1>\u{1F6E1} blocked by veil</h1>
<p><b>${esc(url.hostname)}</b> is on the tracker blocklist.<br><small>${esc(reason)}</small></p>
<a href="javascript:history.back()">&larr; go back</a> &nbsp;·&nbsp; <a href="/">veil home</a>`
      )
    );
  }

  function sendBlockedResource(res, url, acceptHeader, reason) {
    // Resource-shaped lie: just enough for the page to keep working.
    const path = url.pathname.split('?')[0].toLowerCase();
    const ext = path.includes('.') ? path.slice(path.lastIndexOf('.') + 1) : '';
    const a = (acceptHeader || '').toLowerCase();
    res.setHeader('x-veil-blocked', reason);
    if (ext === 'js' || a.includes('javascript')) {
      res.writeHead(200, { 'content-type': 'application/javascript; charset=utf-8' });
      res.end(`/* blocked by veil: ${reason} */`);
      return;
    }
    if (ext === 'css' || a.includes('text/css')) {
      res.writeHead(200, { 'content-type': 'text/css; charset=utf-8' });
      res.end('/* blocked by veil */');
      return;
    }
    if (
      ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'avif', 'ico'].includes(ext) ||
      a.includes('image')
    ) {
      res.writeHead(200, { 'content-type': 'image/gif' });
      res.end(GIF_1PX);
      return;
    }
    if (a.includes('json')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
      return;
    }
    res.writeHead(204, { 'content-type': 'text/plain' });
    res.end();
  }

  async function streamBody(res, up, outHeaders, headOnly) {
    if (headOnly || !up.body) {
      res.writeHead(up.status, outHeaders);
      res.end();
      return;
    }
    res.writeHead(up.status, outHeaders);
    const nodeStream = Readable.fromWeb(up.body);
    nodeStream.on('error', () => res.destroy());
    await new Promise((resolve) => {
      nodeStream.pipe(res, { end: true });
      res.on('finish', resolve);
      res.on('close', resolve);
    });
  }

  function collectOutboundHeaders(up) {
    const drop = new Set([
      'set-cookie', // consumed by the jar
      'content-length', // we recompute or chunk
      'transfer-encoding',
      'content-encoding', // fetch already decoded
      'connection',
      'x-frame-options', // we want the page to render in the browser tab
      'cross-origin-embedder-policy',
      'cross-origin-opener-policy',
      'cross-origin-resource-policy',
      'strict-transport-security',
    ]);
    const out = {};
    for (const [k, v] of up.headers) {
      const lk = k.toLowerCase();
      if (drop.has(lk)) continue;
      if (lk === 'content-security-policy') {
        // Keep CSP but remove frame-ancestors (browsers honor the *innermost*
        // ancestor's policy; ours is the one that applies here).
        const filtered = v.replace(/frame-ancestors[^;]*;?/gi, '').trim();
        if (filtered) out[lk] = filtered;
        continue;
      }
      out[lk] = v;
    }
    return out;
  }

  function consumeSetCookies(up) {
    const lines = up.headers.getSetCookie ? up.headers.getSetCookie() : [];
    let origin, host;
    try {
      const u = new URL(up.url);
      origin = u.origin;
      host = u.hostname;
    } catch {
      return;
    }
    for (const line of lines) cookies.ingest(origin, line, host);
  }

  async function deliver(req, res, up, finalUrl) {
    stats.add('proxied');
    const method = (req.method || 'GET').toUpperCase();
    const noBody = method === 'HEAD' || up.status === 204 || up.status === 304;

    consumeSetCookies(up);
    const outHeaders = collectOutboundHeaders(up);
    const ct = (up.headers.get('content-type') || '').toLowerCase();
    const isHtml = ct.includes('text/html');

    if (isHtml && !noBody) {
      const declared = Number(up.headers.get('content-length') || 0);
      if (!(declared > 0 && declared > MAX_HTML_BYTES)) {
        let buf;
        try {
          buf = Buffer.from(await up.arrayBuffer());
        } catch {
          return streamBody(res, up, outHeaders, true);
        }
        if (buf.length <= MAX_HTML_BYTES) {
          const { html: rewritten, counts } = rewriteHtml(buf.toString('utf8'), up.url);
          stats.add('urlsRewritten', counts.rewritten);
          const finalHtml = injectHud(rewritten, {
            host: new URL(up.url).hostname,
            rewritten: counts.rewritten,
            blockedTotal: stats.snapshot().trackersBlocked,
          });
          outHeaders['content-length'] = Buffer.byteLength(finalHtml, 'utf8');
          res.writeHead(up.status, outHeaders);
          res.end(finalHtml);
          return;
        }
      }
    }
    return streamBody(res, up, outHeaders, noBody);
  }

  return async function handleProxy(req, res, rawTarget) {
    let target;
    try {
      target = new URL(decodeURIComponent(rawTarget));
    } catch {
      return sendError(res, 400, 'malformed /p/ target — use /p/<urlencoded-url>');
    }
    if (target.protocol !== 'http:' && target.protocol !== 'https:') {
      return sendError(res, 400, `scheme ${target.protocol} is not proxied (http/https only)`);
    }

    // Scrub the entry URL.
    const entry = params.strip(target.href);
    if (entry.stripped.length) stats.add('paramsStripped', entry.stripped.length);
    let url = new URL(entry.url);

    const method = (req.method || 'GET').toUpperCase();
    let body = null;
    if (method !== 'GET' && method !== 'HEAD') {
      try {
        body = await readBody(req);
      } catch (e) {
        return sendError(res, 413, e.message);
      }
    }

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      // Blocklist first: we never even talk to known trackers.
      const { blocked, reason } = blocklist.check(url.href);
      if (blocked) {
        stats.add('trackersBlocked');
        stats.recordBlock(url.href, reason);
        const isNavigation = (req.headers.accept || '').toLowerCase().includes('text/html');
        return isNavigation ? sendBlockPage(res, url, reason) : sendBlockedResource(res, url, req.headers.accept, reason);
      }

      try {
        await assertPublicHost(url.hostname, { allowLoopback });
      } catch (e) {
        return sendError(res, 403, e.message);
      }

      const { headers, fetchMode } = buildOutboundHeaders(req.headers, url.href, cookies.forRequest(url.origin), {
        profile: stealthProfile,
      });
      const { ctrl, done } = timeout();
      let up;
      try {
        const init = {
          method,
          headers,
          body,
          redirect: 'manual',
          signal: ctrl.signal,
        };
        if (fetchMode) init.mode = fetchMode;
        up = await fetchImpl(url.href, init);
      } catch (e) {
        done();
        const msg = e.name === 'AbortError' ? `upstream timed out after ${timeoutMs / 1000}s` : `upstream error: ${e.message}`;
        return sendError(res, 502, msg);
      }
      done();

      if ([301, 302, 303, 307, 308].includes(up.status)) {
        const loc = up.headers.get('location');
        if (!loc) return sendError(res, 502, 'redirect without location');
        let next;
        try {
          next = new URL(loc, url.href);
        } catch {
          return sendError(res, 502, 'invalid redirect location');
        }
        if (next.protocol !== 'http:' && next.protocol !== 'https:') {
          return sendError(res, 502, 'redirect to a non-http scheme');
        }
        consumeSetCookies(up);
        const scrubbed = params.strip(next.href);
        if (scrubbed.stripped.length) stats.add('paramsStripped', scrubbed.stripped.length);
        url = new URL(scrubbed.url);
        continue;
      }

      return deliver(req, res, up, url);
    }
    return sendError(res, 502, 'too many redirects');
  };
}
