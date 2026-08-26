// Domain + endpoint blocklist for known trackers and ad tech.

function hostOf(urlString) {
  try {
    return new URL(urlString).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function createBlocklist(cfg = {}) {
  const exact = new Set();
  const suffixes = []; // ".hotjar.io"
  const endpoints = []; // { host, wildcard, prefixes: [], exact: [] }

  for (const h of cfg.hosts || []) {
    const host = String(h).toLowerCase();
    if (host.startsWith('*.')) suffixes.push(host.slice(1)); // keep leading dot
    else exact.add(host);
  }
  for (const e of cfg.endpoints || []) {
    endpoints.push({
      host: String(e.host).toLowerCase(),
      wildcard: Boolean(e.wildcard),
      prefixes: (e.prefixes || []).map((p) => String(p).toLowerCase()),
      exact: (e.exact || []).map((p) => String(p).toLowerCase()),
    });
  }

  function hostMatches(host, ep) {
    if (host === ep.host) return true;
    return ep.wildcard && host.endsWith(`.${ep.host}`);
  }

  /**
   * Returns { blocked: false } or { blocked: true, reason }.
   */
  function check(urlString) {
    const host = hostOf(urlString);
    if (!host) return { blocked: false };

    if (exact.has(host)) return { blocked: true, reason: `host ${host}` };
    for (const suf of suffixes) {
      if (host.endsWith(suf)) return { blocked: true, reason: `host ${host} (suffix ${suf})` };
    }

    let pathname = '';
    try {
      pathname = new URL(urlString).pathname.toLowerCase();
    } catch {
      return { blocked: false };
    }
    for (const ep of endpoints) {
      if (!hostMatches(host, ep)) continue;
      if (ep.exact.includes(pathname) || ep.prefixes.some((p) => pathname.startsWith(p))) {
        return { blocked: true, reason: `tracker endpoint ${host}${pathname}` };
      }
    }
    return { blocked: false };
  }

  return { check };
}
