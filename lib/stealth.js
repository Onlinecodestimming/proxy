// Stealth identity: synthesize the header set a specific mainstream browser
// would send for a given request. The point is NOT to impersonate the user's
// browser — it's to present one stable, common, non-unique identity so no
// per-user fingerprint (or the proxy's own stack) leaks upstream.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const cfgFile = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'config',
  'profiles.json'
);

export function loadProfiles(file = cfgFile) {
  const cfg = JSON.parse(readFileSync(file, 'utf8'));
  return { defaultName: cfg.default || 'chrome-win', profiles: cfg.profiles || {} };
}

/**
 * If `referer` points at one of our own /p/ URLs, decode it back to the
 * upstream URL it represents. Returns that upstream URL string, or null.
 */
export function proxiedRefererToUpstream(referer) {
  if (!referer) return null;
  let u;
  try {
    u = new URL(referer, 'http://placeholder.invalid');
  } catch {
    return null;
  }
  if (!u.pathname.startsWith('/p/')) return null;
  try {
    const decoded = decodeURIComponent(u.pathname.slice(3));
    return new URL(decoded).href;
  } catch {
    return null;
  }
}

/** Classify the request the way a browser's networking layer would. */
export function detectKind({ clientHeaders = {}, url } = {}) {
  const accept = (clientHeaders.accept || '').toLowerCase();
  if (accept.includes('text/html')) return 'document';
  if (accept.includes('text/css')) return 'style';
  if (accept.includes('image/')) return 'image';
  let pathname = '';
  try {
    pathname = new URL(url).pathname.toLowerCase();
  } catch {
    /* no url */
  }
  if (/\.(mjs|cjs|js)$/.test(pathname)) return 'script';
  if (/\.(woff2?|ttf|otf|eot)$/.test(pathname)) return 'font';
  if (/\.(png|jpe?g|gif|webp|avif|svg|ico|bmp)$/.test(pathname)) return 'image';
  return 'other'; // fetch/XHR, API calls, unknown
}

/**
 * Coarse same-site check (eTLD+1 by last two labels — good enough for the
 * overwhelming majority of domains; IDN/multi-label public suffixes may be
 * misclassified, which only affects the sec-fetch-site value).
 */
function siteRelation(fromUrl, toUrl) {
  try {
    const a = new URL(fromUrl);
    const b = new URL(toUrl);
    if (a.origin === b.origin) return 'same-origin';
    const tail = (h) => h.split('.').slice(-2).join('.');
    return tail(a.hostname) === tail(b.hostname) ? 'same-site' : 'cross-site';
  } catch {
    return 'none';
  }
}

/**
 * Build the synthesized header set for one upstream request.
 *
 * NOTE on sec-fetch-mode: browsers only emit mode `navigate` for real
 * navigations, and undici's fetch() treats Sec-Fetch-Mode as a forbidden
 * header — it derives the value from the fetch `mode` option, which only
 * allows cors / no-cors / same-origin. We therefore request `same-origin`
 * for documents (closest available) and the exact browser values elsewhere.
 * Closing that last gap would require a custom HTTP client.
 *
 * @param {object} profile entry from config/profiles.json
 * @param {string} url the upstream request URL
 * @param {string|null} refererUpstream the decoded upstream page URL (or null)
 * @param {object} clientHeaders the incoming client's headers (for kind detection)
 * @returns {{ headers: Record<string,string>, fetchMode: 'cors'|'no-cors'|'same-origin' }}
 */
export function synthesizeHeaders({ profile, url, refererUpstream = null, clientHeaders = {} }) {
  const kind = detectKind({ clientHeaders, url });
  const h = {};

  h['user-agent'] = profile.userAgent;
  if (profile.secChUa) h['sec-ch-ua'] = profile.secChUa;
  if (profile.secChUaMobile !== undefined && profile.secChUaMobile !== null)
    h['sec-ch-ua-mobile'] = profile.secChUaMobile;
  if (profile.secChUaPlatform) h['sec-ch-ua-platform'] = profile.secChUaPlatform;
  if (profile.secChUaPlatformVersion)
    h['sec-ch-ua-platform-version'] = profile.secChUaPlatformVersion;

  h['accept-language'] = profile.acceptLanguage;
  h.accept = (profile.accepts || {})[kind] || '*/*';
  h['accept-encoding'] = profile.acceptEncoding || 'gzip, deflate, br';

  const site = refererUpstream ? siteRelation(refererUpstream, url) : 'none';
  h['sec-fetch-site'] = site;
  const fetchMode =
    kind === 'document'
      ? 'same-origin' // see note above
      : kind === 'script' || kind === 'style' || kind === 'image'
        ? 'no-cors'
        : 'cors';
  h['sec-fetch-dest'] =
    { document: 'document', script: 'script', style: 'style', image: 'image', font: 'font' }[kind] || '';

  if (kind === 'document') {
    h['sec-fetch-user'] = '?1';
    h['upgrade-insecure-requests'] = '1';
  }
  h.priority = (profile.priorities || {})[kind] || 'u=1,i';

  return { headers: h, fetchMode };
}

/**
 * Resolve the stealth profile to use.
 * Precedence: explicit name > VEIL_PROFILE env > config default.
 * 'none'/'off' disables stealth (legacy pass-through headers).
 * Lives here (not in server.js) so serverless adapters can use it without
 * importing the module that reads static files at load time.
 */
export function resolveProfile(name, { defaultName, profiles }) {
  const requested = name !== undefined ? name : process.env.VEIL_PROFILE || defaultName;
  if (!requested || requested === 'none' || requested === 'off') return { name: 'none', profile: null };
  const profile = profiles[requested];
  if (!profile) {
    console.warn(`veil: unknown profile '${requested}' — available: ${Object.keys(profiles).join(', ')} — falling back to pass-through`);
    return { name: 'none', profile: null };
  }
  return { name: requested, profile };
}
