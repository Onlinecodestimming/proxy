// Shared plumbing for Veil's Vercel functions.
//
// Vercel's Node runtime has handed functions either classic node:http
// IncomingMessage/ServerResponse objects (plus request helpers) or
// web-Request-shaped ones, and may change again — so everything here
// normalizes both shapes and writes responses through whichever res is
// available. (Files prefixed with `_` under api/ are not exposed as routes.)

import { Writable } from 'node:stream';

/** Collects a full response written through the classic ServerResponse API. */
export class CaptureRes extends Writable {
  constructor() {
    super();
    this.statusCode = 200;
    this.headers = {};
    this.headersSent = false;
    this.chunks = [];
  }
  writeHead(code, headersOrMessage, maybeHeaders) {
    if (this.headersSent) return this;
    this.statusCode = Number(code);
    const h = typeof headersOrMessage === 'string' ? maybeHeaders : headersOrMessage;
    if (h) for (const [k, v] of Object.entries(h)) this.headers[String(k).toLowerCase()] = v;
    this.headersSent = true;
    return this;
  }
  setHeader(k, v) {
    this.headers[String(k).toLowerCase()] = v;
    return this;
  }
  _write(chunk, enc, cb) {
    this.chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, enc));
    cb();
  }
  _final(cb) {
    cb();
  }
  // NOTE: do NOT clear chunks in destroy() — Node's Writable calls destroy()
  // internally after EVERY 'finish' (to emit 'close'), so overriding it to
  // drop the body silently emptied every streamed response.
  result() {
    return { statusCode: this.statusCode, headers: { ...this.headers }, body: Buffer.concat(this.chunks) };
  }
}

/** Pathname of the request, whichever runtime shape it arrived in. */
export function requestPathname(vreq) {
  const raw = vreq?.url;
  if (!raw) return '';
  try {
    return new URL(raw, 'http://placeholder.invalid').pathname;
  } catch {
    return String(raw);
  }
}

/** Plain lower-cased header map (classic object or web Headers instance). */
export function plainHeaders(vreq) {
  const src = vreq?.headers;
  const out = {};
  if (!src) return out;
  if (typeof src.forEach === 'function' && typeof src.get === 'function' && typeof src.has === 'function') {
    src.forEach((value, key) => {
      const k = String(key).toLowerCase();
      out[k] = out[k] ? `${out[k]}, ${value}` : String(value);
    });
    return out;
  }
  for (const [k, v] of Object.entries(src)) {
    out[String(k).toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}

/**
 * The request body as a Buffer (GET/HEAD -> null), from either runtime shape.
 * Throws 'request body too large' past `maxBytes`.
 */
export async function requestBody(vreq, method, maxBytes = 10 * 1024 * 1024) {
  if (method === 'GET' || method === 'HEAD') return null;
  if (typeof vreq?.arrayBuffer === 'function') {
    try {
      return Buffer.from(await vreq.arrayBuffer());
    } catch {
      return null;
    }
  }
  if (vreq && typeof vreq[Symbol.asyncIterator] === 'function') {
    const chunks = [];
    let size = 0;
    for await (const c of vreq) {
      const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
      size += b.length;
      if (size > maxBytes) throw new Error('request body too large');
      chunks.push(b);
    }
    return Buffer.concat(chunks);
  }
  // Helpers runtime: request.body is a getter that may throw.
  try {
    const b = vreq?.body;
    if (b == null) return null;
    if (Buffer.isBuffer(b)) return b;
    if (typeof b === 'string') return Buffer.from(b);
    return Buffer.from(JSON.stringify(b));
  } catch {
    return null;
  }
}

/** A req object shaped the way lib/proxy.js expects (method, headers, body). */
export function makeProxyReq({ method, headers, body }) {
  return {
    method,
    headers,
    [Symbol.asyncIterator]: async function* () {
      if (body && body.length) yield body;
    },
  };
}

const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** A small error page (same look as the proxy's own). */
export function errorOut(code, message) {
  const body = `<!doctype html><html><head><meta charset="utf-8"><title>veil — ${code}</title></head>
<body style="background:#06080c;color:#c8d6e5;font:15px/1.7 ui-sans-serif,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
<div style="max-width:440px;text-align:center;background:#0c111a;border:1px solid #1c2637;border-radius:16px;padding:36px 32px">
<h1 style="font-size:21px;margin:0 0 10px">${esc(message)}</h1>
<p style="color:#6b7f99;margin:0">🛡 that's an error from veil, not the site.
<a style="color:#5cd6ff" href="javascript:history.back()">&larr; go back</a> &nbsp;·&nbsp; <a style="color:#5cd6ff" href="/">veil home</a></p>
</div></body></html>`;
  return { statusCode: code, headers: { 'content-type': 'text/html; charset=utf-8' }, body: Buffer.from(body, 'utf8') };
}

/**
 * Send a captured result through whichever response object the runtime gave
 * us. Returns the value the handler should return (undefined when the res
 * was written directly; a Response/legacy object on web-shaped runtimes).
 */
export function deliver(vres, out) {
  if (vres && typeof vres.writeHead === 'function' && typeof vres.end === 'function') {
    vres.writeHead(out.statusCode, out.headers);
    vres.end(out.body);
    return undefined;
  }
  if (typeof Response === 'function') {
    return new Response(out.body, { status: out.statusCode, headers: out.headers });
  }
  return { statusCode: out.statusCode, headers: out.headers, body: out.body };
}
