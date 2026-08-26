// Strips marketing/attribution query parameters from URLs.

export function createParamMatcher(cfg = {}) {
  const exact = new Set((cfg.exact || []).map((s) => String(s).toLowerCase()));
  const prefixes = (cfg.prefixes || []).map((s) => String(s).toLowerCase());

  function isTrackingParam(name) {
    const n = String(name).toLowerCase();
    if (exact.has(n)) return true;
    return prefixes.some((p) => n.startsWith(p));
  }

  /**
   * Remove tracking params from a URL string.
   * Returns { url, stripped } where stripped is the list of removed param names.
   * Never throws: unparseable input is returned unchanged.
   */
  function strip(urlString) {
    let u;
    try {
      u = new URL(urlString);
    } catch {
      return { url: urlString, stripped: [] };
    }
    const out = new URL(u.href);
    const stripped = [];
    for (const key of [...out.searchParams.keys()]) {
      if (isTrackingParam(key)) {
        out.searchParams.delete(key); // removes every occurrence
        stripped.push(key);
      }
    }
    return { url: out.href, stripped };
  }

  return { isTrackingParam, strip };
}
