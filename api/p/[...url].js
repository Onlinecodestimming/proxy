// Veil on Vercel: the SAME proxy pipeline as server.js (lib/proxy.js),
// adapted to serverless.
//
// What this changes vs the local server:
//   - no raw sockets -> no CONNECT tunnels, no system-proxy mode; use
//     /p/<urlencoded-url> (the front-page bookmarklet does this for you)
//   - no shared memory -> stats are per-invocation, and upstream session
//     cookies persist in the browser's own cookie jar as veil cookies
//     (lib/cookie-forward.js) instead of an in-memory jar
//   - tighter plan limits -> smaller response cap + shorter upstream timeout
//
// Everything else — param scrubbing, tracker blocklist, cookie policy,
// stealth identity, SSRF guard, redirect re-scrubbing, HTML rewriting — is
// the same code path as `node server.js`.

import { createProxyHandler } from '../../lib/proxy.js';
import { loadConfig } from '../../lib/config.js';
import { createBlocklist } from '../../lib/blocklist.js';
import { createParamMatcher } from '../../lib/params.js';
import { createCookiePolicy, CookieJar } from '../../lib/cookies.js';
import { createStats } from '../../lib/stats.js';
import { resolveProfile } from '../../lib/stealth.js';
import { originTag, parseVeilCookies, veilSetCookies } from '../../lib/cookie-forward.js';
import {
  CaptureRes,
  requestPathname,
  plainHeaders,
  requestBody,
  makeProxyReq,
  deliver,
  errorOut,
} from '../_internal.js';

// Config is IMPORTED (not read from disk) so the bundler ships it with the
// function — a runtime readFileSync would have no file to find on Vercel.
import trackersJson from '../../config/trackers.json' with { type: 'json' };
import paramsJson from '../../config/tracking-params.json' with { type: 'json' };
import cookiesJson from '../../config/tracking-cookies.json' with { type: 'json' };
import profilesJson from '../../config/profiles.json' with { type: 'json' };

// Vercel Hobby caps function responses at 4.5 MB and requests at 10 s;
// stay under both. Pro/Enterprise can raise these via env.
const MAX_RESPONSE_BYTES = Number(process.env.VEIL_MAX_RESPONSE_BYTES) || 4 * 1024 * 1024;
const TIMEOUT_MS = Math.min(Number(process.env.VEIL_TIMEOUT_MS) || 8000, 20000);

export default async function handler(vreq, vres) {
  let pathname;
  try {
    pathname = requestPathname(vreq);
  } catch {
    return deliver(vres, errorOut(400, 'bad request'));
  }
  if (pathname.startsWith('/api/p/')) pathname = '/p/' + pathname.slice(7); // rewritten form
  if (!pathname.startsWith('/p/')) {
    return deliver(vres, errorOut(404, 'not found — /p/<urlencoded-url> is the proxy'));
  }
  const rawTarget = pathname.slice(3);

  const method = String(vreq?.method || 'GET').toUpperCase();
  const headers = plainHeaders(vreq);
  let body = null;
  try {
    body = await requestBody(vreq, method);
  } catch (e) {
    return deliver(vres, errorOut(413, e.message || 'request body too large'));
  }

  // Fresh per-invocation deps (stateless platform — nothing survives).
  const cfg = loadConfig({ trackers: trackersJson, params: paramsJson, cookies: cookiesJson });
  const stats = createStats();
  const cookieJar = new CookieJar(createCookiePolicy(cfg.cookies), stats);
  const { profile: stealthProfile } = resolveProfile(undefined, {
    defaultName: profilesJson.default,
    profiles: profilesJson.profiles,
  });
  const handleProxy = createProxyHandler({
    stats,
    blocklist: createBlocklist(cfg.trackers),
    params: createParamMatcher(cfg.params),
    cookies: cookieJar,
    allowLoopback: process.env.VEIL_ALLOW_LOOPBACK === '1',
    timeoutMs: TIMEOUT_MS,
    stealthProfile,
  });

  // Seed the jar from the veil cookies the browser sent — the persistence
  // layer that replaces the local server's in-memory jar.
  let targetOrigin = null;
  try {
    targetOrigin = new URL(decodeURIComponent(rawTarget)).origin;
  } catch {
    /* malformed target — handleProxy will send its 400 */
  }
  const clientVeil = parseVeilCookies(headers.cookie);
  if (targetOrigin) {
    const tag = originTag(targetOrigin);
    for (const { name, value } of clientVeil.get(tag) ?? []) {
      cookieJar.setRaw(targetOrigin, name, value);
    }
  }

  const capture = new CaptureRes();
  const req = makeProxyReq({ method, headers, body });
  await handleProxy(req, capture, rawTarget).catch((e) => {
    if (!capture.headersSent) {
      capture.writeHead(500, { 'content-type': 'text/plain' });
      capture.end(`veil internal error: ${e.message}`);
    } else {
      capture.end();
    }
  });

  const out = capture.result();

  // Persist whatever this hop stored back into the browser's jar (and clear
  // anything upstream deleted).
  const outSetCookies = [];
  for (const origin of cookieJar.origins()) {
    const tag = originTag(origin);
    const clientNames = (clientVeil.get(tag) ?? []).map((c) => c.veilName);
    outSetCookies.push(...veilSetCookies(origin, cookieJar.allFor(origin), clientNames));
  }
  if (outSetCookies.length) out.headers['set-cookie'] = outSetCookies;

  if (out.body.length > MAX_RESPONSE_BYTES) {
    return deliver(
      vres,
      errorOut(
        502,
        `upstream response too large for this host (${(out.body.length / 1048576).toFixed(1)}MB) — ${
          MAX_RESPONSE_BYTES / 1048576
        }MB cap on this plan; raise VEIL_MAX_RESPONSE_BYTES on Pro`
      )
    );
  }
  return deliver(vres, out);
}
