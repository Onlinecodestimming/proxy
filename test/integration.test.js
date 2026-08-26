import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createVeilServer } from '../server.js';
import { proxyUrlFor } from '../lib/rewrite.js';
import { loadProfiles } from '../lib/stealth.js';

const { defaultName, profiles } = loadProfiles();
const ID = profiles[defaultName]; // the identity veil presents by default

// A mock "upstream" website with a session cookie, a tracking cookie,
// a first-party script, and a tracker under /tracked/.
let mock;
let mockPort;
let veil;
let vport;
const mockRequests = [];

const GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

const MOCK_HTML = (p) => `<!doctype html>
<html><head><title>t</title>
<link rel="stylesheet" href="/site.css">
<script src="/site.js"></script>
<script src="/tracked/ga.js"></script>
<img src="http://127.0.0.1:${p}/tracked/px.gif">
<a href="?utm_source=x&utm_campaign=y&next=/login">login</a>
<a href="/plain">plain</a>
</head><body><p>hello</p></body></html>`;

const listen = (server) =>
  new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));

before(async () => {
  mock = http.createServer((req, res) => {
    mockRequests.push({
      url: req.url,
      method: req.method,
      cookie: req.headers.cookie || null,
      referer: req.headers.referer || null,
      ua: req.headers['user-agent'] || null,
      secChUa: req.headers['sec-ch-ua'] || null,
      accept: req.headers.accept || null,
      secFetchSite: req.headers['sec-fetch-site'] || null,
      secFetchMode: req.headers['sec-fetch-mode'] || null,
      secFetchDest: req.headers['sec-fetch-dest'] || null,
      priority: req.headers.priority || null,
      upgrade: req.headers['upgrade-insecure-requests'] || null,
    });
    const u = new URL(req.url, 'http://127.0.0.1');
    if (u.pathname === '/page') {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'set-cookie': ['_ga=GA1.2.abc123; Path=/', 'session=sess_1; Path=/'],
      });
      res.end(MOCK_HTML(mockPort));
    } else if (u.pathname === '/site.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end('console.log("first-party ok");');
    } else if (u.pathname === '/site.css') {
      res.writeHead(200, { 'content-type': 'text/css' });
      res.end('body{color:rebeccapurple}');
    } else if (u.pathname === '/tracked/ga.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end('/* TRACKER RAN */ window.__tracked = true;');
    } else if (u.pathname === '/tracked/px.gif') {
      res.writeHead(200, { 'content-type': 'image/gif' });
      res.end(GIF);
    } else if (u.pathname === '/redirect') {
      res.writeHead(302, { location: '/page?utm_source=z' }); // relative redirect
      res.end();
    } else {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('nope');
    }
  });
  mockPort = await listen(mock);

  veil = createVeilServer({
    allowLoopback: true,
    trackers: {
      hosts: [],
      endpoints: [{ host: '127.0.0.1', wildcard: true, prefixes: ['/tracked/'], exact: [] }],
      paths: { prefixes: ['/_px/', '/D/1/'], exact: [] },
    },
  });
  vport = await listen(veil.server);
});

after(() => {
  mock.close();
  veil.server.close();
});

const up = (p) => `http://127.0.0.1:${mockPort}${p}`;
const px = (target) => `http://127.0.0.1:${vport}/p/` + encodeURIComponent(target);

test('navigation: HTML is rewritten, cookies are filtered, params are scrubbed', async () => {
  const r = await fetch(px(`${up('/page')}?utm_source=ads&fbclid=zz&keep=1`), {
    // a real browser's navigation request: browser-like Accept, plus a
    // client identity that veil must not forward
    headers: {
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'user-agent': 'TestBrowser/9',
      'sec-ch-ua': '"WeirdBrowser";v="1"',
      'accept-language': 'de-DE',
    },
  });
  assert.equal(r.status, 200);
  assert.ok((r.headers.get('content-type') || '').includes('text/html'));
  assert.equal(r.headers.get('set-cookie'), null); // never exposed to the browser
  const html = await r.text();

  // Resources now route through the proxy.
  assert.ok(html.includes(proxyUrlFor(up('/site.js'))));
  assert.ok(html.includes(proxyUrlFor(up('/site.css'))));
  assert.ok(html.includes(proxyUrlFor(up('/tracked/ga.js')))); // rewritten, then blocked on request
  assert.ok(html.includes(proxyUrlFor(`${up('/page')}?utm_source=x&utm_campaign=y&next=/login`)));
  // HUD badge injected
  assert.ok(html.includes('id="veil-hud"'));

  // The mock saw the synthesized identity: entry tracking params stripped,
  // no cookies yet, and NOT a trace of the client's real device.
  const req = mockRequests[mockRequests.length - 1];
  assert.equal(req.url, '/page?keep=1'); // utm_source + fbclid stripped
  assert.equal(req.cookie, null);
  assert.equal(req.ua, ID.userAgent); // stealth profile, not 'TestBrowser/9'
  assert.equal(req.secChUa, ID.secChUa);
  assert.ok(!JSON.stringify(req).includes('TestBrowser'));
  // sec-fetch context for a top-level navigation
  assert.equal(req.secFetchSite, 'none');
  assert.equal(req.secFetchDest, 'document');
  assert.equal(req.secFetchMode, 'same-origin'); // undici can't emit 'navigate' (see stealth.js)
  assert.equal(req.priority, ID.priorities.document);
  assert.equal(req.upgrade, '1');
});

test('second request carries the session cookie, never the tracking one', async () => {
  await fetch(px(up('/page')));
  const req = mockRequests[mockRequests.length - 1];
  assert.equal(req.cookie, 'session=sess_1');
});

test('blocked tracker: never fetched upstream, resource-shaped stub returned', async () => {
  const before = mockRequests.length;
  const r = await fetch(px(up('/tracked/ga.js')));
  assert.equal(r.status, 200);
  assert.ok((r.headers.get('content-type') || '').includes('javascript'));
  assert.ok((r.headers.get('x-veil-blocked') || '').includes('/tracked/ga.js'));
  assert.equal(mockRequests.length, before); // upstream never saw it
});

test('blocked image gets a 1x1 gif', async () => {
  const r = await fetch(px(up('/tracked/px.gif')));
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('content-type'), 'image/gif');
  assert.equal(Buffer.from(await r.arrayBuffer()).length, GIF.length);
});

test('navigation to a blocked host gets a block page', async () => {
  const r = await fetch(px(up('/tracked/ga.js')), { headers: { accept: 'text/html' } });
  assert.equal(r.status, 200);
  const html = await r.text();
  assert.ok(html.includes('blocked by veil'));
});

test('redirect hops are followed and re-scrubbed (relative location resolved)', async () => {
  const r = await fetch(px(up('/redirect')));
  assert.equal(r.status, 200);
  const req = mockRequests[mockRequests.length - 1];
  // Location was '/page?utm_source=z' (relative) — resolved, then scrubbed to bare '/page'
  assert.equal(req.url, '/page');
  assert.ok(!req.url.includes('utm_source'));
});

test('referer is decoded and reduced to the bare upstream origin; subresources get script context', async () => {
  const pagePx = `http://127.0.0.1:${vport}${proxyUrlFor(up('/page'))}`;
  await fetch(px(up('/site.js')), {
    headers: {
      referer: pagePx,
      accept: '*/*', // what a browser sends for <script src>
    },
  });
  const req = mockRequests[mockRequests.length - 1];
  assert.equal(req.referer, `http://127.0.0.1:${mockPort}/`);
  assert.equal(req.secFetchDest, 'script');
  assert.equal(req.secFetchSite, 'same-origin');
  assert.equal(req.secFetchMode, 'no-cors'); // browser-exact for classic scripts
  assert.equal(req.ua, ID.userAgent); // same identity as the page load
});

test('guardian sensor uploads are blocked on any host (global path rules)', async () => {
  for (const p of ['/_px/v4/sensor-payload', '/D/1/token123']) {
    const before = mockRequests.length;
    const r = await fetch(px(`${up(p)}`));
    assert.notEqual(r.status, 404, p); // answered by veil, not the mock
    assert.ok(r.headers.get('x-veil-blocked'), p);
    assert.equal(mockRequests.length, before, `${p} must never reach upstream`);
  }
});

test('SSRF: internal targets are refused before any network call', async () => {
  // allowLoopback is on for this server (mock is on 127.0.0.1), but
  // cloud metadata and private ranges stay blocked.
  for (const target of ['http://169.254.169.254/latest/meta-data/', 'http://10.0.0.1/', 'http://172.16.5.5/']) {
    const r = await fetch(px(target));
    assert.equal(r.status, 403, target);
  }
});

test('system-proxy mode: absolute-form HTTP request is proxied and scrubbed', async () => {
  // what a browser sends when veil is configured as its HTTP proxy
  const r = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: vport,
        method: 'GET',
        path: `http://127.0.0.1:${mockPort}/page?utm_source=x&keep=1`, // absolute-form
        headers: { accept: 'text/html,*/*' },
      },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode, body }));
      }
    );
    req.on('error', reject);
    req.end();
  });
  assert.equal(r.status, 200);
  assert.ok(r.body.includes('id="veil-hud"'));
  const req = mockRequests[mockRequests.length - 1];
  assert.equal(req.url, '/page?keep=1'); // utm_source stripped
});

function connectTunnel(target, getLine, getHeaders = {}) {
  // raw-socket CONNECT through the proxy, then one raw GET inside the tunnel
  return new Promise((resolve, reject) => {
    const sock = net.connect(vport, '127.0.0.1');
    let buf = '';
    let established = false;
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error('tunnel timeout'));
    }, 5000);
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (!established && (buf.includes(' 200 ') || buf.includes(' 403 '))) {
        if (buf.includes(' 403 ')) {
          clearTimeout(timer);
          sock.end();
          return resolve({ blocked: true, buf });
        }
        established = true;
        const h = Object.entries(getHeaders)
          .map(([k, v]) => `${k}: ${v}`)
          .join('\r\n');
        sock.write(`${getLine}\r\nHost: ${target}\r\n${h ? h + '\r\n' : ''}Connection: close\r\n\r\n`);
      } else if (established && (buf.includes('</html>') || / 404 /.test(buf))) {
        clearTimeout(timer);
        sock.end();
        resolve({ blocked: false, buf });
      }
    });
    sock.on('error', reject);
    sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
  });
}

test('system-proxy mode: CONNECT tunnels (IP masked, honestly blind) + SSRF-guarded', async () => {
  const r = await connectTunnel(
    `127.0.0.1:${mockPort}`,
    'GET /page?utm_source=untouched HTTP/1.1',
    { 'User-Agent': 'RAW-CLIENT/1' }
  );
  assert.equal(r.blocked, false);
  assert.ok(r.buf.includes('<!doctype html>')); // the mock's raw page, straight through
  const req = mockRequests[mockRequests.length - 1];
  assert.equal(req.url, '/page?utm_source=untouched'); // NOT scrubbed — tunnel is blind
  assert.equal(req.ua, 'RAW-CLIENT/1'); // NOT the stealth identity — blind tunnel

  // internal targets are refused even for tunnels
  const bad = await connectTunnel('169.254.169.254:80', 'GET / HTTP/1.1');
  assert.equal(bad.blocked, true);
});

test('telemetry: counters reflect what happened', async () => {
  const s = await (await fetch(`http://127.0.0.1:${vport}/stats`)).json();
  assert.ok(s.proxied >= 4);
  assert.ok(s.tunneled >= 1);
  assert.ok(s.trackersBlocked >= 3);
  assert.ok(s.paramsStripped >= 3);
  assert.ok(s.cookiesStripped >= 1);
  assert.ok(s.cookiesStored >= 1);
  assert.ok(s.urlsRewritten >= 4);
  assert.ok(s.recentBlocks.length >= 1);
});

test('front page and 404s', async () => {
  const home = await (await fetch(`http://127.0.0.1:${vport}/`)).text();
  assert.ok(home.includes('veil'));
  assert.equal((await fetch(`http://127.0.0.1:${vport}/nope`)).status, 404);
});
