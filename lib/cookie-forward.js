// Serverless cookie persistence.
//
// A stateless host (e.g. Vercel) has no in-memory cookie jar across
// invocations, so upstream session cookies would vanish between requests.
// Instead we persist them in the ONE store that IS shared between serverless
// invocations and belongs to the user: the browser's own cookie jar, on
// Veil's own origin.
//
//   upstream `session=abc; Path=/` for https://shop.example
//     -> veil  Set-Cookie: vh_<sha256(origin)[:16]>_session=abc; Path=/; HttpOnly; Secure
//
// Every request to /p/ brings those cookies back (browsers send all cookies
// for the veil origin); we decode the ones whose tag matches the target
// origin and forward them upstream. Tracking cookies never make it into the
// jar (the cookie policy is applied both at storage time and at re-seed
// time), values are URL-encoded so they survive the Cookie-header round trip
// intact, and each cookie is capped below the browser's per-cookie limit.

import { createHash } from 'node:crypto';

export const VEIL_COOKIE_PREFIX = 'vh_';
const TAG_LEN = 16;
const MAX_VALUE_CHARS = 3800; // browser per-cookie limit is ~4096

/** Stable per-origin tag: first 16 hex chars of SHA-256 of the origin string. */
export function originTag(origin) {
  return createHash('sha256').update(String(origin)).digest('hex').slice(0, TAG_LEN);
}

const safeName = (n) => String(n).replace(/[^A-Za-z0-9._-]/g, '_') || 'c';

/**
 * Parse a client Cookie header into Map<tag, [{name, value, veilName}> for
 * the veil cookies it contains (non-veil cookies are ignored).
 */
export function parseVeilCookies(cookieHeader) {
  const out = new Map();
  if (!cookieHeader) return out;
  const re = new RegExp(`^${VEIL_COOKIE_PREFIX}([0-9a-f]{${TAG_LEN}})_(.+)$`);
  for (const part of String(cookieHeader).split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    const veilName = part.slice(0, i).trim();
    const m = veilName.match(re);
    if (!m) continue;
    let value = part.slice(i + 1).trim();
    try {
      value = decodeURIComponent(value);
    } catch {
      /* undecodable — keep raw */
    }
    const list = out.get(m[1]) ?? [];
    list.push({ name: m[2], value, veilName });
    out.set(m[1], list);
  }
  return out;
}

/**
 * Build the veil Set-Cookie lines that persist `entries` (from
 * CookieJar.allFor) for `origin`, plus Max-Age=0 deletions for
 * `staleNames` — veil cookie names the client still holds but the jar no
 * longer has (the upstream cleared them).
 */
export function veilSetCookies(origin, entries, staleNames = []) {
  const tag = originTag(origin);
  const now = Date.now();
  const lines = [];
  const seen = new Set();
  for (const { name, value, expires } of entries) {
    const veilName = `${VEIL_COOKIE_PREFIX}${tag}_${safeName(name)}`;
    seen.add(veilName);
    let enc;
    try {
      enc = encodeURIComponent(String(value));
    } catch {
      continue;
    }
    if (enc.length > MAX_VALUE_CHARS) continue; // can't fit in one cookie
    let lifetime = '';
    if (expires !== null && expires !== undefined) {
      const maxAge = Math.floor((expires - now) / 1000);
      lifetime = maxAge <= 0 ? '; Max-Age=0' : `; Max-Age=${maxAge}`;
    }
    lines.push(`${veilName}=${enc}; Path=/; HttpOnly; Secure${lifetime}`);
  }
  for (const veilName of staleNames) {
    if (seen.has(veilName)) continue;
    lines.push(`${veilName}=; Path=/; HttpOnly; Secure; Max-Age=0`);
  }
  return lines;
}
