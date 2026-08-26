// Cookie policy (which names are tracking) + an in-memory, origin-scoped cookie jar.
//
// Cookies are scoped per-origin (scheme://host:port). This is intentionally
// stricter than browser semantics (which honor the Domain attribute): it stops
// cookie-based cross-subdomain tracking as a side effect.

const MAX_COOKIES_PER_ORIGIN = 200;

export function createCookiePolicy(cfg = {}) {
  const rules = (cfg.rules || []).map((r) => ({
    name: r.name ? String(r.name).toLowerCase() : null,
    prefix: r.prefix ? String(r.prefix).toLowerCase() : null,
    domain: r.domain ? String(r.domain).toLowerCase() : null,
  }));

  function domainOk(ruleHost, host) {
    if (!ruleHost) return true;
    return host === ruleHost || host.endsWith(`.${ruleHost}`);
  }

  function isTrackingCookie(name, host) {
    const n = String(name).toLowerCase();
    const h = String(host || '').toLowerCase();
    return rules.some(
      (r) =>
        domainOk(r.domain, h) &&
        ((r.name && r.name === n) || (r.prefix && n.startsWith(r.prefix)))
    );
  }

  return { isTrackingCookie };
}

export class CookieJar {
  constructor(policy, stats = { add() {} }) {
    this.policy = policy;
    this.stats = stats;
    this.map = new Map(); // origin -> Map(name -> { value, expires })
  }

  /**
   * Consume one Set-Cookie header line coming from `origin` (host used for
   * domain-scoped policy rules). Returns 'stored' | 'stripped' | 'cleared' | 'ignored'.
   */
  ingest(origin, setCookieLine, host) {
    const first = String(setCookieLine).split(';')[0];
    const eq = first.indexOf('=');
    if (eq < 1) return 'ignored';
    const name = first.slice(0, eq).trim();
    const value = first.slice(eq + 1).trim();
    if (!name) return 'ignored';

    let expires = null;
    for (const part of String(setCookieLine).split(';').slice(1)) {
      const i = part.indexOf('=');
      const k = (i === -1 ? part : part.slice(0, i)).trim().toLowerCase();
      const v = (i === -1 ? '' : part.slice(i + 1)).trim();
      if (k === 'expires') {
        const t = Date.parse(v);
        if (!Number.isNaN(t)) expires = t;
      } else if (k === 'max-age') {
        const n = Number(v);
        if (!Number.isNaN(n)) expires = Date.now() + n * 1000;
      }
    }

    const lname = name.toLowerCase();
    const jar = this.map.get(origin) ?? new Map();

    // Expiry in the past => deletion.
    if (expires !== null && expires <= Date.now()) {
      jar.delete(lname);
      if (jar.size) this.map.set(origin, jar);
      else this.map.delete(origin);
      return 'cleared';
    }

    if (this.policy.isTrackingCookie(name, host)) {
      this.stats.add('cookiesStripped');
      return 'stripped';
    }

    if (jar.size >= MAX_COOKIES_PER_ORIGIN) {
      // Overflow: drop the origin's whole jar rather than keep growing.
      this.map.delete(origin);
      return 'ignored';
    }
    jar.set(lname, { value, expires });
    this.map.set(origin, jar);
    this.stats.add('cookiesStored');
    return 'stored';
  }

  /** Cookie header value for requests to `origin`, or null. */
  forRequest(origin) {
    const jar = this.map.get(origin);
    if (!jar) return null;
    const now = Date.now();
    const parts = [];
    for (const [n, c] of jar) {
      if (c.expires !== null && c.expires <= now) {
        jar.delete(n);
        continue;
      }
      parts.push(`${n}=${c.value}`);
    }
    if (!parts.length) {
      this.map.delete(origin);
      return null;
    }
    return parts.join('; ');
  }

  clear() {
    this.map.clear();
  }
}
