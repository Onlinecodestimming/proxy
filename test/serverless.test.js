import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { originTag, parseVeilCookies, veilSetCookies } from '../lib/cookie-forward.js';
import { CookieJar, createCookiePolicy } from '../lib/cookies.js';
import { CaptureRes } from '../api/_internal.js';

const listen = (server) =>
  new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));

// ---- unit: veil cookie encode/decode -------------------------------------

test('cookie-forward: origin tag is stable, distinct, and a 16-hex string', () => {
  const a = originTag('https://shop.example');
  const b = originTag('https://shop.example');
  const c = originTag('https://other.example');
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^[0-9a-f]{16}$/);
});

test('cookie-forward: parses veil cookies from a client Cookie header, ignores the rest', () => {
  const tag = originTag('https://shop.example');
  const header = `vh_${tag}_session=${encodeURIComponent('a b=c')}; other=ignore; vh_${tag}_next=2`;
  const m = parseVeilCookies(header);
  assert.equal(m.size, 1); // 'other' is not a veil cookie
  assert.deepEqual(m.get(tag), [
    { name: 'session', value: 'a b=c', veilName: `vh_${tag}_session` },
    { name: 'next', value: '2', veilName: `vh_${tag}_next` },
  ]);
});

test('cookie-forward: Set-Cookie lines persist, expire, delete, and cap', () => {
  const origin = 'https://shop.example';
  const tag = originTag(origin);
  const lines = veilSetCookies(
    origin,
    [
      { name: 'session', value: 'x=1', expires: null },
      { name: 'tmp', value: 'y', expires: Date.now() + 60_000 },
      { name: 'dead', value: 'z', expires: Date.now() - 1000 },
    ],
    [`vh_${tag}_gone`]
  );
  assert.equal(lines.length, 4);
  assert.ok(lines[0].startsWith(`vh_${tag}_session=x%3D1; Path=/; HttpOnly; Secure`));
  assert.match(lines[1], new RegExp(`vh_${tag}_tmp=y; Path=/; HttpOnly; Secure; Max-Age=\\d{1,3}$`));
  assert.ok(lines[2].endsWith('; Max-Age=0')); // already expired upstream -> clear locally
  assert.equal(lines[3], `vh_${tag}_gone=; Path=/; HttpOnly; Secure; Max-Age=0`); // client stale
  // a value that can't fit in one browser cookie is dropped, not truncated
  const huge = veilSetCookies(origin, [{ name: 'big', value: 'x'.repeat(5000), expires: null }]);
  assert.equal(huge.length, 0);
});

test('jar: setRaw/allFor/origins round-trip and still apply the tracking policy', () => {
  const jar = new CookieJar(createCookiePolicy({ rules: [{ prefix: '_ga' }] }));
  assert.equal(jar.setRaw('https://shop.example', 'session', 'abc'), 'stored');
  assert.equal(jar.setRaw('https://shop.example', '_ga', 'GA1.2.x'), 'stripped');
  assert.deepEqual(jar.origins(), ['https://shop.example']);
  assert.deepEqual(jar.allFor('https://shop.example'), [
    { name: 'session', value: 'abc', expires: null },
  ]);
});

// ---- integration: the real function handler against a local upstream -----

let mock;
let mockPort;
const seen = [];

before(async () => {
  mock = http.createServer((req, res) => {
    seen.push({ url: req.url, cookie: req.headers.cookie || null, ua: req.headers['user-agent'] || null });
    const u = new URL(req.url, 'http://127.0.0.1');
    if (u.pathname === '/page') {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'set-cookie': ['_ga=GA1.2.abc123; Path=/', 'session=sess_1; Path=/'],
      });
      res.end(
        '<!doctype html><html><head><title>t</title></head><body><p>hello</p><a href="?utm_source=x">l</a></body></html>'
      );
    } else if (u.pathname === '/cookie-echo') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('cookie-header: ' + (req.headers.cookie || '(none)'));
    } else {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('nope');
    }
  });
  mockPort = await listen(mock);
  process.env.VEIL_ALLOW_LOOPBACK = '1'; // mock upstream is on 127.0.0.1
});

after(() => {
  mock.close();
  delete process.env.VEIL_ALLOW_LOOPBACK;
});

const { default: handler } = await import('../api/p/[...url].js');
const { default: statsHandler } = await import('../api/stats.js');

// classic node:http-shaped request/response, the way older Vercel runtimes
// (and our tests) hand them in
function classicReq({ url, method = 'GET', headers = {} }) {
  return { url, method, headers, [Symbol.asyncIterator]: async function* () {} };
}

const statusOf = (out) => (out instanceof Response ? out.status : out.statusCode);
const textOf = async (out) => (out instanceof Response ? out.text() : out.body.toString('utf8'));

test('serverless: full pipeline — params scrubbed, stealth identity, veil cookies out', async () => {
  const target = `http://127.0.0.1:${mockPort}/page?utm_source=ads&keep=1`;
  const res = new CaptureRes();
  const ret = await handler(
    classicReq({
      url: '/p/' + encodeURIComponent(target),
      headers: {
        accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'user-agent': 'Client-Browser/9',
        'accept-language': 'fr-FR',
      },
    }),
    res
  );
  assert.equal(ret, undefined); // classic res was written directly
  const out = res.result();
  assert.equal(out.statusCode, 200);
  const html = out.body.toString('utf8');
  assert.ok(html.includes('id="veil-hud"'), 'HUD injected');
  assert.ok(html.includes('/p/'), 'sub-resource links re-anchored through the proxy');

  const setCookies = out.headers['set-cookie'] || [];
  const tag = originTag(`http://127.0.0.1:${mockPort}`);
  assert.ok(
    setCookies.some((l) => l.startsWith(`vh_${tag}_session=sess_1;`)),
    `session cookie persisted as veil cookie (got: ${JSON.stringify(setCookies)})`
  );
  assert.ok(!setCookies.some((l) => l.includes('_ga')), 'tracking cookie never persisted');

  const m = seen[seen.length - 1];
  assert.equal(m.url, '/page?keep=1'); // utm_source stripped
  assert.ok(!m.ua.includes('Client-Browser'), 'stealth identity out, not the client UA');
});

test('serverless: persisted veil cookies are sent upstream on the next request', async () => {
  const tag = originTag(`http://127.0.0.1:${mockPort}`);
  const res = new CaptureRes();
  await handler(
    classicReq({
      url: '/p/' + encodeURIComponent(`http://127.0.0.1:${mockPort}/cookie-echo`),
      headers: { cookie: `vh_${tag}_session=sess_1`, accept: '*/*' },
    }),
    res
  );
  const out = res.result();
  assert.equal(out.statusCode, 200);
  assert.ok(out.body.toString('utf8').includes('session=sess_1'), 'echo saw the forwarded cookie');
  assert.equal(seen[seen.length - 1].cookie, 'session=sess_1');
});

test('serverless: rewritten /api/p/ path form works too (vercel.json destination)', async () => {
  const res = new CaptureRes();
  await handler(
    classicReq({
      url: '/api/p/' + encodeURIComponent(`http://127.0.0.1:${mockPort}/cookie-echo`),
      headers: { accept: '*/*' },
    }),
    res
  );
  assert.equal(res.result().statusCode, 200);
});

test('serverless: SSRF guard still refuses internal targets without the loopback env', async () => {
  delete process.env.VEIL_ALLOW_LOOPBACK;
  try {
    const res = new CaptureRes();
    await handler(
      classicReq({
        url: '/p/' + encodeURIComponent('http://127.0.0.1:9/whatever'),
        headers: { accept: 'text/html' },
      }),
      res
    );
    assert.equal(res.result().statusCode, 403);
  } finally {
    process.env.VEIL_ALLOW_LOOPBACK = '1'; // restore for any later tests
  }
});

test('serverless: web-shaped (fetch Request) input works too', async () => {
  const r = new Request('http://veil.example/p/' + encodeURIComponent(`http://127.0.0.1:${mockPort}/page`), {
    headers: { accept: 'text/html' },
  });
  const out = await handler(r, undefined); // no classic res -> returned value
  assert.equal(statusOf(out), 200);
  assert.ok((await textOf(out)).includes('id="veil-hud"'));
});

test('serverless: /stats reports serverless mode (and reset is a no-op)', async () => {
  const out = statsHandler(classicReq({ url: '/stats' }), undefined);
  assert.equal(statusOf(out), 200);
  const s = JSON.parse(await textOf(out));
  assert.equal(s.serverless, true);
  assert.deepEqual(s.recentBlocks, []);

  const reset = statsHandler(classicReq({ url: '/stats/reset' }), undefined);
  assert.equal(statusOf(reset), 200);
  assert.equal(JSON.parse(await textOf(reset)).ok, true);
});
