// Builds the set of headers that leave toward the upstream site.
//
// Strategy: start from nothing and copy only what helps the page work,
// dropping everything that identifies the client or leaks context:
//   - sec-ch-ua* (client hints = browser fingerprint)
//   - sec-fetch-*  (embedding context)
//   - origin       (cross-site context leak)
//   - referer      (replaced by upstream-origin-only referer)
//   - any cookie the jar didn't approve

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

export function buildOutboundHeaders(clientHeaders = {}, targetUrlString, cookieHeader) {
  const h = {};
  h['accept-encoding'] = 'gzip, deflate, br';

  const ua = process.env.VEIL_USER_AGENT || clientHeaders['user-agent'];
  if (ua) h['user-agent'] = ua;

  const al = process.env.VEIL_ACCEPT_LANGUAGE || clientHeaders['accept-language'];
  if (al) h['accept-language'] = al;

  if (clientHeaders.accept) h.accept = clientHeaders.accept;

  // Conditional / range headers: safe to pass, keep 304s working.
  for (const k of ['if-modified-since', 'if-none-match', 'range', 'if-range']) {
    if (clientHeaders[k]) h[k] = clientHeaders[k];
  }

  // Referer: only when it came from the same upstream origin, and then only
  // the bare origin (no deep path, no proxied URL).
  try {
    const targetOrigin = new URL(targetUrlString).origin;
    const upstreamRef = proxiedRefererToUpstream(clientHeaders.referer);
    if (upstreamRef && new URL(upstreamRef).origin === targetOrigin) {
      h.referer = `${targetOrigin}/`;
    }
  } catch {
    /* no referer */
  }

  if (cookieHeader) h.cookie = cookieHeader;

  h.dnt = '1';
  h['referrer-policy'] = 'no-referrer';
  return h;
}
