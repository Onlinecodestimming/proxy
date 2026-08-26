import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createParamMatcher } from '../lib/params.js';
import { createBlocklist } from '../lib/blocklist.js';
import { createCookiePolicy } from '../lib/cookies.js';
import { rewriteHtml, proxyUrlFor } from '../lib/rewrite.js';
import { isPrivateIp, isLoopbackIp, assertPublicHost, SsrfError } from '../lib/ssrf.js';
import { buildOutboundHeaders, proxiedRefererToUpstream } from '../lib/headers.js';

const PARAMS = {
  exact: ['fbclid', 'gclid', 'dclid', 'mc_cid', 'mkt_tok', 'spm', 'ref', '_gl', 'igshid', 'yclid'],
  prefixes: ['utm_', 'hsa_', '_branch_', 'af_sub', 'mtm_'],
};
const params = createParamMatcher(PARAMS);

test('params: strips known attribution params, keeps the rest', () => {
  const { url, stripped } = params.strip(
    'https://shop.example.com/item?utm_source=ads&utm_medium=cpc&fbclid=ABC&id=42&name=café'
  );
  assert.equal(stripped.sort().join(','), 'fbclid,utm_medium,utm_source');
  const u = new URL(url);
  assert.equal(u.searchParams.get('id'), '42');
  assert.equal(u.searchParams.get('name'), 'café');
  assert.equal(u.searchParams.has('utm_source'), false);
});

test('params: matching is case-insensitive and prefix-aware', () => {
  assert.equal(params.isTrackingParam('UTM_SOURCE'), true);
  assert.equal(params.isTrackingParam('hsa_cam'), true);
  assert.equal(params.isTrackingParam('mtm_campaign'), true);
  assert.equal(params.isTrackingParam('af_sub1'), true);
  assert.equal(params.isTrackingParam('utm'), false);
  assert.equal(params.isTrackingParam('utmfoo'), false); // prefix is "utm_", not "utm"
  assert.equal(params.isTrackingParam('product_ref'), false);
});

test('params: duplicate keys all removed, unparseable input passes through', () => {
  const { stripped } = params.strip('https://x.test/a?utm_source=1&utm_source=2&keep=1');
  assert.equal(stripped.length, 2);
  assert.deepEqual(params.strip('not a url'), { url: 'not a url', stripped: [] });
});

const TRACKERS = {
  hosts: [
    'doubleclick.net',
    '*.doubleclick.net',
    'hotjar.com',
    '*.hotjar.io',
    'clarity.ms',
    'analytics.tiktok.com',
  ],
  endpoints: [
    { host: 'google.com', wildcard: true, prefixes: ['/ads/', '/pagead/'], exact: [] },
    { host: 'facebook.com', wildcard: true, prefixes: [], exact: ['/tr', '/fbevents.js'] },
  ],
};
const bl = createBlocklist(TRACKERS);

test('blocklist: exact + wildcard host matches', () => {
  assert.equal(bl.check('https://doubleclick.net/x').blocked, true);
  assert.equal(bl.check('https://g.doubleclick.net/x').blocked, true);
  assert.equal(bl.check('https://www.doubleclick-evil.net/x').blocked, false); // suffix must include dot
  assert.equal(bl.check('https://hotjar.com/').blocked, true);
  assert.equal(bl.check('https://static.hotjar.io/a.js').blocked, true);
  assert.equal(bl.check('https://notclarity.ms.com/').blocked, false);
  assert.equal(bl.check('https://analytics.tiktok.com/api/pixel').blocked, true);
});

test('blocklist: endpoint rules by path, prefix and exact', () => {
  assert.equal(bl.check('https://www.google.com/pagead/js/adsbygoogle.js').blocked, true);
  // wildcard host: a google.com subdomain is subject to the same endpoint rules
  assert.equal(bl.check('https://ads.google.com/pagead/x').blocked, true);
  assert.equal(bl.check('https://ads.google.com/x').blocked, false); // path must also match
  assert.equal(bl.check('https://www.google.com/search?q=veil').blocked, false);
  assert.equal(bl.check('https://facebook.com/tr?id=123').blocked, true);
  assert.equal(bl.check('https://www.facebook.com/tree-of-life').blocked, false); // "/tr" is exact only
  assert.equal(bl.check('https://m.facebook.com/fbevents.js').blocked, true);
  assert.equal(bl.check('https://facebook.com/').blocked, false);
});

const COOKIES = {
  rules: [
    { name: '_ga' },
    { prefix: '_gcl_' },
    { name: 'fr', domain: 'facebook.com' },
    { prefix: '_mkto_' },
  ],
};
const pol = createCookiePolicy(COOKIES);

test('cookies: name, prefix and domain-scoped rules', () => {
  assert.equal(pol.isTrackingCookie('_ga', 'example.com'), true);
  assert.equal(pol.isTrackingCookie('_gcl_au', 'example.com'), true);
  assert.equal(pol.isTrackingCookie('_mkto_trk', 'example.com'), true);
  assert.equal(pol.isTrackingCookie('fr', 'facebook.com'), true);
  assert.equal(pol.isTrackingCookie('fr', 'www.facebook.com'), true);
  assert.equal(pol.isTrackingCookie('fr', 'example.com'), false); // generic name only on facebook
  assert.equal(pol.isTrackingCookie('session', 'example.com'), false);
  assert.equal(pol.isTrackingCookie('_GA', 'example.com'), true); // case-insensitive
});

test('rewrite: relative, absolute and protocol-relative URLs become /p/ URLs', () => {
  const base = 'https://site.example.com/deep/page?x=1';
  const { html, counts } = rewriteHtml(
    `<html><body>
      <a href="/login?a=b&amp;c=d">l</a>
      <img src="//cdn.example.com/p.png">
      <script src="https://other.example.com/x.js"></script>
      <video poster="poster.jpg"></video>
      <a href="mailto:x@y.z">m</a>
      <a href="data:text/plain;base64,xx">d</a>
      <a href="#frag">f</a>
    </body></html>`,
    base
  );
  assert.ok(html.includes(proxyUrlFor('https://site.example.com/login?a=b&c=d')));
  assert.ok(html.includes(proxyUrlFor('https://cdn.example.com/p.png')));
  assert.ok(html.includes(proxyUrlFor('https://other.example.com/x.js')));
  assert.ok(html.includes(proxyUrlFor('https://site.example.com/deep/poster.jpg')));
  assert.ok(html.includes('href="mailto:x@y.z"'));
  assert.ok(html.includes('href="data:text/plain;base64,xx"'));
  assert.ok(html.includes('href="#frag"'));
  assert.equal(counts.rewritten, 4);
});

test('rewrite: entities round-trip, srcset descriptors preserved', () => {
  const base = 'https://s.example.com/p';
  const { html } = rewriteHtml(
    `<img srcset="/a.png 1x, /b.png 2x" src="/a.png"><a href="/u?q=1&amp;r=2">u</a>`,
    base
  );
  assert.ok(html.includes(proxyUrlFor('https://s.example.com/a.png') + ' 1x'));
  assert.ok(html.includes(proxyUrlFor('https://s.example.com/b.png') + ' 2x'));
  assert.ok(html.includes(proxyUrlFor('https://s.example.com/u?q=1&r=2')));
});

test('rewrite: <base href> and meta refresh are rewritten', () => {
  const base = 'https://s.example.com/app';
  const { html } = rewriteHtml(
    `<head><base href="/app/"></head><body>
       <meta http-equiv="refresh" content="2; url=next">
       <a href="rel">rel</a>
       <a href="/abs">abs</a>
     </body>`,
    base
  );
  // base tag itself
  assert.ok(html.includes(proxyUrlFor('https://s.example.com/app/')));
  // relative refs resolve against the base directory
  assert.ok(html.includes(proxyUrlFor('https://s.example.com/app/next')));
  assert.ok(html.includes(proxyUrlFor('https://s.example.com/app/rel')));
  // absolute-path refs ignore the base path
  assert.ok(html.includes(proxyUrlFor('https://s.example.com/abs')));
});

test('rewrite: already-proxied URLs are not double-wrapped', () => {
  const base = 'https://s.example.com/';
  const already = proxyUrlFor('https://s.example.com/x');
  const { html } = rewriteHtml(`<a href="${already}">a</a>`, base);
  assert.ok(html.includes(`href="${already}"`));
  assert.ok(!html.includes(proxyUrlFor(already)));
});

test('rewrite: script/style/comment content is never touched, but script src is', () => {
  const base = 'https://s.example.com/';
  const inner = `var tpl = '<a href="http://evil.example/hook">x</a>"; // href="http://evil.example/nested"';`;
  const { html, counts } = rewriteHtml(
    `<html><head><style>.a{content:"href='http://evil.example/css'"}</style>
     <script src="https://ext.example.com/lib.js"></script>
     <script>${inner}</script>
     <!-- href="http://evil.example/cmt" -->
     <title>href="http://evil.example/t"</title>
     </head><body><a href="/real">ok</a></body></html>`,
    base
  );
  // JS string content must NOT be rewritten...
  assert.ok(!html.includes(proxyUrlFor('http://evil.example/hook')));
  assert.ok(html.includes('http://evil.example/hook'));
  // ...but the external script's src attribute MUST route through the proxy
  assert.ok(html.includes(proxyUrlFor('https://ext.example.com/lib.js')));
  assert.ok(!html.includes(proxyUrlFor('http://evil.example/css')));
  assert.ok(!html.includes(proxyUrlFor('http://evil.example/cmt')));
  assert.ok(html.includes(proxyUrlFor('https://s.example.com/real')));
  assert.equal(counts.rewritten, 2);
});

test('ssrf: private/loopback/link-local/reserved detection', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '198.19.5.5', '255.255.255.255']) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
  // 100.64.0.0/10 CGNAT covers second octet 64..127, so 100.127.x is inside, 100.128.x is out
  assert.equal(isPrivateIp('100.127.0.1'), true);
  for (const ip of ['93.184.216.34', '8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1']) {
    assert.equal(isPrivateIp(ip), false, ip);
  }
  assert.equal(isPrivateIp('::1'), true);
  assert.equal(isPrivateIp('fe80::1'), true);
  assert.equal(isPrivateIp('fd00::1'), true);
  assert.equal(isPrivateIp('2001:4860:4860::8888'), false);
  assert.equal(isLoopbackIp('127.0.0.1'), true);
  assert.equal(isLoopbackIp('::1'), true);
  assert.equal(isLoopbackIp('8.8.8.8'), false);
});

test('ssrf: assertPublicHost blocks internal targets (URL normalization covers tricks)', async () => {
  const fakeDns = async () => [{ address: '93.184.216.34' }];
  await assertPublicHost('example.com', { lookup: fakeDns });
  await assertPublicHost('93.184.216.34');
  // WHATWG URL normalization already converts 0x7f000001 & friends to 127.0.0.1 before we see it
  assert.equal(new URL('http://0x7f000001/').hostname, '127.0.0.1');

  await assert.rejects(() => assertPublicHost('127.0.0.1'), SsrfError);
  await assert.rejects(() => assertPublicHost('169.254.169.254'), SsrfError);
  await assert.rejects(() => assertPublicHost('10.0.0.1'), SsrfError);
  await assert.rejects(() => assertPublicHost('localhost'), SsrfError);
  // DNS answers pointing inside
  await assert.rejects(
    () => assertPublicHost('evil.example', { lookup: async () => [{ address: '10.0.0.2' }] }),
    SsrfError
  );
  // allowLoopback opens only loopback — cloud metadata stays blocked
  await assertPublicHost('127.0.0.1', { allowLoopback: true });
  await assertPublicHost('localhost', { allowLoopback: true });
  await assert.rejects(() => assertPublicHost('169.254.169.254', { allowLoopback: true }), SsrfError);
  await assert.rejects(() => assertPublicHost('10.0.0.1', { allowLoopback: true }), SsrfError);
});

test('headers: fingerprint & context headers dropped, safe ones kept', () => {
  const clientHeaders = {
    'user-agent': 'TestAgent/1.0',
    'accept-language': 'de-DE,de;q=0.9',
    accept: 'text/html',
    'sec-ch-ua': '"Chromium";v="120"',
    'sec-fetch-site': 'same-origin',
    origin: 'https://site.example.com',
    referer: `https://proxy.example${proxyUrlFor('https://site.example.com/old')}`,
    'if-modified-since': 'Mon, 01 Jan 2024 00:00:00 GMT',
    cookie: 'should-not-pass=1',
  };
  const h = buildOutboundHeaders(clientHeaders, 'https://site.example.com/new', null);
  assert.equal(h['user-agent'], 'TestAgent/1.0');
  assert.equal(h['accept-language'], 'de-DE,de;q=0.9');
  assert.equal(h.accept, 'text/html');
  assert.equal(h.referer, 'https://site.example.com/'); // bare upstream origin, no path
  assert.equal(h['if-modified-since'], 'Mon, 01 Jan 2024 00:00:00 GMT');
  assert.equal(h.cookie, undefined);
  assert.equal(h['sec-ch-ua'], undefined);
  assert.equal(h['sec-fetch-site'], undefined);
  assert.equal(h.origin, undefined);
  assert.equal(h.dnt, '1');
});

test('headers: cross-origin referer is dropped entirely', () => {
  const h = buildOutboundHeaders(
    { referer: `https://proxy.example${proxyUrlFor('https://other.example.com/a')}` },
    'https://site.example.com/b',
    null
  );
  assert.equal(h.referer, undefined);
});

test('headers: proxiedRefererToUpstream decodes /p/ URLs, ignores others', () => {
  assert.equal(
    proxiedRefererToUpstream(`https://p.example${proxyUrlFor('https://s.example.com/x')}`),
    'https://s.example.com/x'
  );
  assert.equal(proxiedRefererToUpstream('https://s.example.com/x'), null);
  assert.equal(proxiedRefererToUpstream('https://p.example/p/not%'), null);
});
