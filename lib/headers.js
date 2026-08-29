// Builds the set of headers that leave toward the upstream site.
//
// With a stealth profile (the default): Veil presents ONE consistent
// mainstream-browser identity — UA, client hints, sec-fetch-*, Accept,
// Accept-Language, Priority — derived per request. Nothing from the client's
// real device or from the proxy's stack goes out.
//
// Without a profile ('none'): pass-through of the client's identity headers
// (legacy behavior).

import { proxiedRefererToUpstream as decodeReferer, synthesizeHeaders } from './stealth.js';

/**
 * If `referer` points at one of our own /p/ URLs, decode it back to the
 * upstream URL it represents. Returns that upstream URL string, or null.
 */
export { decodeReferer as proxiedRefererToUpstream };

const SYNTH_OWNED = new Set(['accept-encoding', 'user-agent', 'accept', 'accept-language']);

export function buildOutboundHeaders(clientHeaders = {}, targetUrlString, cookieHeader, { profile = null } = {}) {
  const h = {};

  let refererUpstream = null;
  try {
    refererUpstream = decodeReferer(clientHeaders.referer);
  } catch {
    /* no referer */
  }

  const { headers: synth, fetchMode } = profile
    ? synthesizeHeaders({ profile, url: targetUrlString, refererUpstream, clientHeaders })
    : { headers: {}, fetchMode: undefined };

  for (const [k, v] of Object.entries(synth)) {
    if (v === '' && k === 'sec-fetch-dest') continue; // browser sends empty; omit
    h[k] = v;
  }

  if (profile) {
    // Env override beats the profile; profile beats the client's identity.
    if (process.env.VEIL_USER_AGENT) h['user-agent'] = process.env.VEIL_USER_AGENT;
    if (process.env.VEIL_ACCEPT_LANGUAGE) h['accept-language'] = process.env.VEIL_ACCEPT_LANGUAGE;
  } else {
    const ua = process.env.VEIL_USER_AGENT || clientHeaders['user-agent'];
    if (ua) h['user-agent'] = ua;
    const al = process.env.VEIL_ACCEPT_LANGUAGE || clientHeaders['accept-language'];
    if (al) h['accept-language'] = al;
    if (clientHeaders.accept && !h.accept) h.accept = clientHeaders.accept;
    h['accept-encoding'] = h['accept-encoding'] || 'gzip, deflate, br';
  }

  // Conditional / range headers: safe to pass, keep 304s working.
  for (const k of ['if-modified-since', 'if-none-match', 'range', 'if-range']) {
    if (clientHeaders[k]) h[k] = clientHeaders[k];
  }

  // Referer: only when it came from the same upstream origin, and then only
  // the bare origin (no deep path, no proxied URL).
  try {
    const targetOrigin = new URL(targetUrlString).origin;
    if (refererUpstream && new URL(refererUpstream).origin === targetOrigin) {
      h.referer = `${targetOrigin}/`;
    }
  } catch {
    /* no referer */
  }

  if (cookieHeader) h.cookie = cookieHeader;
  return { headers: h, fetchMode };
}
