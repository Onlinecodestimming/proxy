// SSRF guard: refuse to fetch loopback / private / link-local / reserved
// addresses, including ones reached via DNS. The proxy must never become a
// hole into the machine it runs on (metadata endpoints, admin UIs, ...).

import dns from 'node:dns';
import net from 'node:net';

const stripBrackets = (h) => String(h || '').replace(/^\[|\]$/g, '');

export function isLoopbackIp(ip) {
  const s = stripBrackets(ip).toLowerCase();
  const kind = net.isIP(s);
  if (kind === 4) return s.startsWith('127.');
  if (kind === 6) return s === '::1' || s === '::ffff:127.0.0.1' || s.startsWith('::ffff:127.');
  return false;
}

export function isPrivateIp(ip) {
  const s = stripBrackets(ip).toLowerCase();
  const kind = net.isIP(s);
  if (kind === 4) {
    const parts = s.split('.').map(Number);
    const [a, b] = parts;
    return (
      a === 0 || // 0.0.0.0/8
      a === 10 || // 10.0.0.0/8
      a === 127 || // 127.0.0.0/8
      (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 CGNAT
      (a === 169 && b === 254) || // 169.254.0.0/16 link-local (cloud metadata!)
      (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
      (a === 192 && b === 168) || // 192.168.0.0/16
      (a === 198 && (b === 18 || b === 19)) || // 198.18.0.0/15 benchmarking
      a >= 224 // multicast + reserved + 255.255.255.255
    );
  }
  if (kind === 6) {
    if (s === '::' || s === '::1') return true;
    // fe80::/10 link-local, fc00::/7 unique-local
    if (/^fe[89ab]/.test(s) || s.startsWith('fc') || s.startsWith('fd')) return true;
    if (s.startsWith('64:ff9b')) return true; // NAT64
    const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    return false;
  }
  return true; // not an IP at all -> treat as unsafe
}

export class SsrfError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SsrfError';
  }
}

/**
 * Ensure `hostname` is a public internet host.
 * @param {string} hostname URL hostname (may be an IP literal, with [v6] brackets)
 * @param {object} [opts]
 * @param {boolean} [opts.allowLoopback] permit 127.0.0.0/8, ::1 and *.localhost
 *                                       (still blocks CGNAT/link-local/private)
 * @param {(host, opts) => Promise<Array<{address: string}>>} [opts.lookup] injectable DNS
 */
export async function assertPublicHost(hostname, { allowLoopback = false, lookup = dns.promises.lookup } = {}) {
  const host = stripBrackets(String(hostname || '')).toLowerCase();
  if (!host) throw new SsrfError('empty host');

  if (host === 'localhost' || host.endsWith('.localhost') || host === 'localhost.localdomain') {
    if (!allowLoopback) throw new SsrfError('loopback host not allowed');
    return;
  }

  if (net.isIP(host)) {
    if (isLoopbackIp(host)) {
      if (!allowLoopback) throw new SsrfError('loopback address not allowed');
      return;
    }
    if (isPrivateIp(host)) throw new SsrfError('internal address not allowed');
    return;
  }

  let results;
  try {
    results = await lookup(host, { all: true, verbatim: true });
  } catch (e) {
    throw new SsrfError(`dns lookup failed for ${host}: ${e.message}`);
  }
  for (const r of results) {
    if (isLoopbackIp(r.address)) {
      if (!allowLoopback) throw new SsrfError(`host resolves to loopback (${r.address})`);
      continue;
    }
    if (isPrivateIp(r.address)) throw new SsrfError(`host resolves to internal address (${r.address})`);
  }
}
