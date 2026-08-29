#!/usr/bin/env node
// Veil — zero-dependency anti-tracking web proxy.
//
//   /            front page
//   /p/<url>     proxy target (url is encodeURIComponent(url))
//   GET http://… absolute-form proxy request (system-proxy mode)
//   CONNECT      blind TLS tunnel (IP masking only — see README)
//   /stats       JSON counters  ·  /stats/reset zeroes them

import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadConfig } from './lib/config.js';
import { createStats } from './lib/stats.js';
import { createBlocklist } from './lib/blocklist.js';
import { createParamMatcher } from './lib/params.js';
import { createCookiePolicy, CookieJar } from './lib/cookies.js';
import { createProxyHandler } from './lib/proxy.js';
import { loadProfiles, resolveProfile } from './lib/stealth.js';
import { assertPublicHost } from './lib/ssrf.js';

export { resolveProfile };

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'static', 'index.html'), 'utf8');
const FIXTURE_GMAIL_HTML = fs.readFileSync(path.join(__dirname, 'static', 'fixtures', 'gmail-mock.html'), 'utf8');

export function createVeilServer({ allowLoopback = false, fetchImpl, trackers, params, cookies, profile } = {}) {
  const cfg = loadConfig({ trackers, params, cookies });
  const { defaultName, profiles } = loadProfiles();
  const { name: profileName, profile: stealthProfile } = resolveProfile(profile, { defaultName, profiles });
  const stats = createStats();
  const blocklist = createBlocklist(cfg.trackers);
  const paramsMatcher = createParamMatcher(cfg.params);
  const cookieJar = new CookieJar(createCookiePolicy(cfg.cookies), stats);
  const handleProxy = createProxyHandler({
    stats,
    blocklist,
    params: paramsMatcher,
    cookies: cookieJar,
    allowLoopback,
    fetchImpl,
    stealthProfile,
  });

  function route(req, res) {
    // System-proxy absolute-form request: the browser sends the target URL
    // itself ("GET http://site.com/page HTTP/1.1") when Veil is configured
    // as its HTTP proxy.
    if (/^https?:\/\//i.test(req.url)) {
      let target;
      try {
        target = new URL(req.url);
      } catch {
        res.writeHead(400, { 'content-type': 'text/plain' });
        res.end('bad request');
        return;
      }
      handleProxy(req, res, encodeURIComponent(target.href)).catch((err) => {
        if (!res.headersSent) {
          res.writeHead(500, { 'content-type': 'text/plain' });
          res.end(`veil internal error: ${err.message}`);
        } else {
          res.end();
        }
      });
      return;
    }

    let u;
    try {
      u = new URL(req.url, 'http://placeholder.invalid');
    } catch {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('bad request');
      return;
    }
    const p = u.pathname;

    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(INDEX_HTML);
      return;
    }
    if (req.method === 'GET' && p === '/stats') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(stats.snapshot(), null, 2));
      return;
    }
    if (req.method === 'GET' && p === '/stats/reset') {
      stats.reset();
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
      return;
    }
    if (req.method === 'GET' && p === '/favicon.ico') {
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method === 'GET' && (p === '/fixtures/gmail' || p === '/fixtures/gmail.html')) {
      // Screen-capture test fixture (see README "Test fixtures"): a clearly
      // labeled mock inbox with live clock/frame counter and resolution tests.
      // Deliberately no sign-in form and no credential fields of any kind.
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(FIXTURE_GMAIL_HTML);
      return;
    }
    if (p.startsWith('/p/')) {
      handleProxy(req, res, p.slice(3)).catch((err) => {
        if (!res.headersSent) {
          res.writeHead(500, { 'content-type': 'text/plain' });
          res.end(`veil internal error: ${err.message}`);
        } else {
          res.end();
        }
      });
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found — / is home, /p/<urlencoded-url> is the proxy, /stats is telemetry');
  }

  const server = http.createServer((req, res) => {
    try {
      route(req, res);
    } catch (err) {
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'text/plain' });
        res.end(`veil internal error: ${err.message}`);
      } else {
        res.end();
      }
    }
  });

  // CONNECT: used by browsers for HTTPS when Veil is their system proxy.
  // This is a BLIND tunnel: bytes pass through untouched, so the site sees
  // Veil's egress IP (masking) but gets NO sanitization — the browser talks
  // to the site directly inside the tunnel. Full HTTPS sanitization only
  // happens via the /p/ flow (front page), which is the protected mode.
  server.on('connect', (req, clientSocket, head) => {
    const [host, portStr] = String(req.url || '').split(':');
    const port = Number(portStr || 443);
    if (!host || Number.isNaN(port) || port < 1 || port > 65535) {
      clientSocket.write('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    assertPublicHost(host, { allowLoopback }).then(() => {
      const upstream = net.connect(port, host, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        stats.add('tunneled');
        if (head && head.length) upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      upstream.on('error', () => clientSocket.destroy());
      clientSocket.on('error', () => upstream.destroy());
      upstream.on('close', () => clientSocket.destroy());
      clientSocket.on('close', () => upstream.destroy());
    }).catch((e) => {
      const body = String(e.message || 'forbidden');
      clientSocket.write(
        `HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\n\r\n${body}`
      );
      clientSocket.destroy();
    });
  });

  return { server, stats, cookieJar, handleProxy, profileName };
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMain) {
  const { server, profileName } = createVeilServer({
    allowLoopback: process.env.VEIL_ALLOW_LOOPBACK === '1',
  });
  const port = Number(process.env.PORT || 3000);
  const host = process.env.HOST || '0.0.0.0';
  server.listen(port, host, () => {
    console.log(`\u{1F6E1} veil anti-tracking proxy listening on http://${host}:${port}`);
    console.log(`   stealth identity: ${profileName}`);
    console.log('   front page:  http://localhost:' + port + '/');
  });
}
