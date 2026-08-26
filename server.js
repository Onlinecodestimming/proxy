#!/usr/bin/env node
// Veil — zero-dependency anti-tracking web proxy.
//
//   /            front page
//   /p/<url>     proxy target (url is encodeURIComponent(url))
//   /stats       JSON counters  ·  /stats/reset zeroes them

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadConfig } from './lib/config.js';
import { createStats } from './lib/stats.js';
import { createBlocklist } from './lib/blocklist.js';
import { createParamMatcher } from './lib/params.js';
import { createCookiePolicy, CookieJar } from './lib/cookies.js';
import { createProxyHandler } from './lib/proxy.js';
import { loadProfiles } from './lib/stealth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'static', 'index.html'), 'utf8');

/**
 * Resolve the stealth profile to use.
 * Precedence: explicit option > VEIL_PROFILE env > config default.
 * 'none'/'off' disables stealth (legacy pass-through headers).
 */
export function resolveProfile(name, { defaultName, profiles }) {
  const requested = name !== undefined ? name : process.env.VEIL_PROFILE || defaultName;
  if (!requested || requested === 'none' || requested === 'off') return { name: 'none', profile: null };
  const profile = profiles[requested];
  if (!profile) {
    console.warn(`veil: unknown profile '${requested}' — available: ${Object.keys(profiles).join(', ')} — falling back to pass-through`);
    return { name: 'none', profile: null };
  }
  return { name: requested, profile };
}

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
    if (p === '/favicon.ico') {
      res.writeHead(204);
      res.end();
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
