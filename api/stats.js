// /stats and /stats/reset on serverless.
//
// There is no shared state between invocations (each request may land in a
// cold, throwaway instance), so cross-request counters are always zero. The
// front page detects `serverless: true` and shows a notice instead of
// pretending.

import { requestPathname, deliver } from './_internal.js';

const BASE = {
  serverless: true,
  proxied: 0,
  tunneled: 0,
  trackersBlocked: 0,
  paramsStripped: 0,
  cookiesStripped: 0,
  cookiesStored: 0,
  urlsRewritten: 0,
  recentBlocks: [],
  note: 'serverless mode: each request runs in its own cold instance, so there is nothing to count across requests',
};

export default function handler(vreq, vres) {
  let pathname = '';
  try {
    pathname = requestPathname(vreq);
  } catch {
    /* fall through — treated as /stats */
  }
  if (pathname === '/stats/reset' || pathname === '/api/stats/reset') {
    return deliver(vres, {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: Buffer.from(JSON.stringify({ ok: true, note: BASE.note }, null, 2)),
    });
  }
  return deliver(vres, {
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    body: Buffer.from(JSON.stringify(BASE, null, 2)),
  });
}
