// In-memory counters for what Veil has done. Nothing is ever written to disk.

export function createStats() {
  const counters = {
    proxied: 0,
    trackersBlocked: 0,
    paramsStripped: 0,
    cookiesStripped: 0,
    cookiesStored: 0,
    urlsRewritten: 0,
  };
  const recentBlocks = []; // { ts, url, reason }
  const MAX_RECENT = 200;

  return {
    startedAt: Date.now(),

    add(key, n = 1) {
      if (Object.prototype.hasOwnProperty.call(counters, key)) counters[key] += n;
    },

    recordBlock(url, reason) {
      recentBlocks.push({ ts: Date.now(), url, reason });
      if (recentBlocks.length > MAX_RECENT) recentBlocks.shift();
    },

    snapshot() {
      return {
        startedAt: this.startedAt,
        ...counters,
        recentBlocks: recentBlocks.slice(-50).reverse(),
      };
    },

    reset() {
      for (const k of Object.keys(counters)) counters[k] = 0;
      recentBlocks.length = 0;
    },
  };
}
