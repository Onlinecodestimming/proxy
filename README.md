# 🛡 veil — anti-tracking web proxy

A zero-dependency Node.js proxy that scrubs the web before it reaches you. Point your
browser at it, enter any URL, and every hop is sanitized:

```
browser ──▶ /p/<urlencoded-url> ──▶ veil ──▶ upstream site
              │  strip tracking params
              │  refuse known tracker domains (never even fetched)
              │  present ONE synthesized browser identity (stealth profile)
              │  drop leaking referrers / Origin
              │  block bot 'guardian' sensor uploads (DataDome, PerimeterX, …)
              │  per-origin cookie jar that eats tracking cookies
              │  re-scrub every redirect hop
              │  rewrite HTML so sub-resources route back through veil
              ▼
           your browser gets the same-origin, sanitized page
```

## Quick start

```sh
node server.js          # or: npm start
# 🛡 veil anti-tracking proxy listening on http://0.0.0.0:3000
```

Open `http://localhost:3000`, paste a link, browse. Tests: `npm test`.

| Env var                | Default       | Meaning                                              |
| ---------------------- | ------------- | ---------------------------------------------------- |
| `PORT` / `HOST`        | `3000` / `0.0.0.0` | bind address                                  |
| `VEIL_PROFILE`         | `chrome-win`  | stealth identity to present upstream — `chrome-win`, `firefox-win`, or `none` (pass the client's own headers through) |
| `VEIL_USER_AGENT`      | *(profile's)* | override the User-Agent specifically                 |
| `VEIL_ACCEPT_LANGUAGE` | *(profile's)* | override Accept-Language specifically                |
| `VEIL_ALLOW_LOOPBACK`  | off           | permit `127.0.0.0/8`/`::1` targets (for local testing) |

## What it strips, hop by hop

- **Tracking query params** on entry URLs *and* every redirect — `utm_*`, `fbclid`,
  `gclid`/`gbraid`/`wbraid`/`dclid`, `mc_cid`, `mkt_tok`, `hsa_*`, `_gl`, `yclid`,
  `igshid`, `_branch_*`, … (`config/tracking-params.json`)
- **Tracker domains** are refused *before* any network call: GA, GTM, Google Ads,
  DoubleClick, Microsoft Clarity, Hotjar, Segment, Mixpanel, Amplitude, Criteo,
  Taboola, Quantcast, Adobe/omtrdc, New Relic, Sentry ingest, ~100 more, plus
  endpoint rules on safe hosts (`facebook.com/tr`, `google.com/pagead/`, …).
  Blocked scripts get an empty JS stub, blocked images a 1×1 gif, so pages keep
  working (`config/trackers.json`)
- **Tracking cookies** — `_ga*`, `_fbp`, `_mkto_*`, `demdex`, `amcv_*`, `_cl*`,
  `fr` (Facebook-scoped), … are dropped from `Set-Cookie`; ordinary session
  cookies are kept in an in-memory, **origin-scoped** jar (stricter than browser
  `Domain=` semantics: no cross-subdomain cookie leakage by design)
  (`config/tracking-cookies.json`)
- **Stealth browser identity** — instead of leaking your real `User-Agent` or
  the proxy's own stack, Veil presents one stable mainstream-browser profile
  (`chrome-win` by default, `firefox-win` available, `none` for pass-through).
  UA, client hints (`Sec-Ch-Ua*`), `Accept`, `Accept-Language`, `Priority`,
  `Upgrade-Insecure-Requests` and the `sec-fetch-site/mode/dest/user` context
  are all synthesized per request and kept mutually consistent, so there is no
  per-user fingerprint and no "this is a proxy" tell. `Origin` is dropped and
  `Referer` is reduced to the upstream site's own bare origin.
- **Bot 'guardian' sensors** — on-site and off-site telemetry of the
  anti-bot / bot-detection systems is blocked before it can leave:
  DataDome (`/D/1/`, `*.datadome.co`), PerimeterX (`/_px/`, `*.pxchk.net`),
  Kasada (`/kas/`, `*.kasada.io`), Akamai (`/akam/`, `*.akstat.io`),
  Imperva/Incapsula (`/_Incapsula_Resource`), F5 Shape (`/Shape`), plus
  challenge/captcha delivery (Cloudflare Turnstile, reCAPTCHA, hCaptcha,
  Arkose). Trade-off: sites that *actively challenge* visitors may show a
  stuck challenge — see `config/trackers.json` (`$guardian`) to remove any of
  these if you'd rather get challenged than be seen.
- **HTML rewriting** — `src`/`href`/`action`/`poster`/`data-src`/`srcset`/`<base>`/
  meta-refresh all re-anchor through the proxy so the policies above apply to
  sub-resources and the page renders same-origin. `X-Frame-Options` and CSP
  `frame-ancestors` are dropped so the page actually displays
- **SSRF guard** — loopback, RFC1918, CGNAT, link-local (cloud metadata!), and
  reserved ranges are refused, including via DNS answers

Telemetry (all in-memory, nothing written to disk): `GET /stats`, reset with
`GET /stats/reset`. The front page shows live counters and a "recently blocked"
feed.

## Using it in a browser (drop-in modes)

Requirements: **Node ≥ 18.17** (20+ recommended), that's it — no `npm install`,
no build step. Copy the folder anywhere and `node server.js`. (No local
server at all? [Deploy to Vercel](#deploying-to-vercel-serverless-mode) —
different feature set, same pipeline.)

**Mode 1 — front page (recommended: fully protected)**
Open `http://localhost:3000` and browse from there. The page **and every
sub-resource** it loads go through Veil: params, trackers, cookies, identity —
all sanitized. This is the mode that does everything.

**Mode 2 — point your system/browser proxy at it (everything flows, split protection)**
Configure `127.0.0.1:3000` as your HTTP(S) proxy:

- **macOS**: System Settings → Network → your connection → Proxies → Web Proxy (HTTP) + Secure Web Proxy (HTTPS) → `127.0.0.1` : `3000`
- **Windows**: Settings → Network & Internet → Proxy → Manual script/manual address → `127.0.0.1:3000`
- **Firefox**: Settings → Network Settings → Manual proxy → `127.0.0.1` : `3000` (leave "no proxy for" empty)
- **Chromium**: launch with `--proxy-server="http=127.0.0.1:3000;https=127.0.0.1:3000"`

What each protocol gets in this mode:

| Traffic | Protection |
| ------- | ---------- |
| `http://` sites | **fully sanitized** (absolute-form requests are proxied like `/p/`) |
| `https://` sites | **IP masking only** — Veil answers `CONNECT` with a blind TLS tunnel. Your IP is hidden behind the proxy's, but the browser talks to the site directly inside the tunnel: no param/cookie/tracker/identity sanitization |

Veil deliberately does **not** MITM HTTPS (that would require installing a
custom root CA trusted with *everything* you type). If you want full
protection for HTTPS, use Mode 1 for that site.

## Endpoints

| Path             | Purpose                                    |
| ---------------- | ------------------------------------------ |
| `/`              | front page                                 |
| `/p/<urlencoded-url>` | proxy target (how all rewriting works) |
| `GET http://…`   | absolute-form proxy request (Mode 2, HTTP) |
| `CONNECT host:port` | blind TLS tunnel (Mode 2, HTTPS — IP mask only) |
| `/stats`         | JSON counters + recent blocks              |
| `/stats/reset`   | zero the counters                          |

## Deploying to Vercel (serverless mode)

Yes — Veil deploys to Vercel. But Vercel runs stateless request handlers, not
a long-lived process, so the repo ships a serverless adapter (`api/`) that
runs the **exact same proxy pipeline** as `server.js` — same param scrubbing,
tracker blocklist, cookie policy, stealth identity, SSRF guard, redirect
re-scrubbing, HTML rewriting — plus a `vercel.json` that maps the clean URLs
(`/p/…`, `/stats`, `/`, `/fixtures/gmail`) onto the functions.

- **Dashboard**: Vercel → *Add New Project* → import this repo → framework
  preset **Other** (auto-detected) → Deploy. No build step, no env vars needed.
- **CLI**: `npx vercel` from the repo root.

What you get on Vercel:

| Works | Notes |
| ----- | ----- |
| `/` front page + **bookmarklet** | drag the bookmarklet to your bookmarks bar; on any site, click it and the page reloads through this deployment |
| `/p/<urlencoded-url>` | the full proxy, fully sanitized |
| stealth identity | same synthesized browser headers; set `VEIL_PROFILE` (`chrome-win`/`firefox-win`/`none`) in Vercel project env to switch |
| sessions, no database | upstream session cookies persist **in your browser's own cookie jar** on the veil origin (`vh_…` cookies, `lib/cookie-forward.js`) — nothing to configure, no KV needed |
| `/stats`, `/fixtures/gmail` | work; the front page shows a "serverless mode" notice |

What Vercel physically cannot do, and what Veil therefore drops there:

- **CONNECT tunnels / system-proxy mode** — serverless functions get no raw
  sockets, so "set Veil as my system proxy" doesn't exist on Vercel. Use the
  front-page bookmarklet instead.
- **Persistent stats** — nothing survives between invocations.
- **Pages over 4 MB** — Hobby caps function responses at 4.5 MB
  (`VEIL_MAX_RESPONSE_BYTES` raises it on Pro, where the cap is higher).
- **10 s request timeout** on Hobby (`VEIL_TIMEOUT_MS` tunes the upstream
  fetch to stay under it; Pro allows longer).
- **Egress IP** is Vercel's shared cloud range — see the honest-limitations
  list below.

`npm start` on a VPS / Railway / Render / your laptop remains the
full-featured mode: tunnels, persistent stats, bigger pages, longer timeouts.

**One warning**: a Vercel deployment is a **public URL**. Anyone who finds it
can use it as their anonymous proxy — your function invocations and bandwidth
bill, their browsing. Keep it personal (or put auth in front) — same rule as
the local server's "no auth" note.

## Honest limitations

A proxy cannot do the impossible. Veil does **not**:

- stop **first-party** tracking (the site itself logging you server-side),
- prevent **JS fingerprinting** that runs inside pages it couldn't block
  (canvas/WebGL/audio) — known tracker scripts are removed at the network layer,
  which kills most of the tooling, but in-page measurement of *you* by code that
  did load is out of reach,
- see inside inline `<script>`/`<style>` bodies (they're left untouched, on
  purpose — third-party trackers are caught at the network layer instead),
- protect websockets or anything non-HTTP,
- **hide the proxy's egress IP** — sites see the proxy's IP, not yours, which
  is better, but it is still a real IP that can be (and is) scored by bot
  systems. Pair with a residential/Tor egress if the IP itself must not be
  attributable,
- **fake the TLS/HTTP2 fingerprint** — a determined "guardian" doing JA3/JA4
  or HTTP2 SETTINGS analysis can still tell a Node `fetch` handshake from a
  real Chrome one. The HTTP *headers* are fully browser-consistent (see above);
  the *transport-layer* fingerprint of the Node TLS stack is not spoofable
  without a custom TLS client. For that threat model, a real browser + an
  extension (uBlock, etc.) or Tor Browser is the stronger tool,
- emit `Sec-Fetch-Mode: navigate` for document loads — undici's `fetch()`
  treats that header as UA-owned and only allows `cors`/`no-cors`/
  `same-origin`. Veil sends `same-origin` for documents (closest available)
  and the exact browser values for every sub-resource type,
- route upstream through an HTTP(S) egress proxy (outbound goes direct;
  in a restricted network the proxy sees what the host can reach).

Treat it as "a lot less tracking, and a boring identity", not "invisible to
a nation-state".

## Test fixtures (for monitoring-tool QA)

`GET /fixtures/gmail` serves a **screen-capture test fixture**: a page that
structurally resembles the Gmail inbox UI, filled with obviously-fake mail,
and instrumented for capture verification:

- a live clock (1 s tick) + frame counter (100 ms) — a stale capture shows
  them frozen
- 8pt fine-print and Greek-letter rows — resolution/downscale checks
- color squares — color sampling checks
- a deliberately non-real "PII" row (SSN `000-00-0000`) — tests PII redaction

Point your own monitoring/capture tool at it and check what it actually sees.
Useful QA insight it encodes: **screen capture alone is not the whole
picture** — the URL bar and activity feed reveal what a page really is, so a
monitor that only records pixels is weaker than one that also logs URLs and
processes.

What the fixture is **not**: it has no sign-in form, no credential fields of
any kind, and is clearly labeled on-screen. It is a test double for your own
tools on machines you monitor — not a page to run at someone being
supervised.

## Security notes

- No dependencies, no build step — Node ≥ 18.17 (`fetch`, `node:test`).
- The proxy has **no auth**. It's for personal/local use; don't expose it to
  the open internet without putting something in front of it.
- Don't use it to break a site's terms or the law.

## Layout

```
server.js            entrypoint + routing (resolves the stealth profile)
lib/proxy.js         proxy engine (fetch loop, redirects, responses)
lib/stealth.js       synthesized browser identity + request-kind detection + profile resolution
lib/headers.js       outbound header assembly (stealth on/off)
lib/rewrite.js       HTML URL rewriting + HUD badge
lib/cookies.js       tracking-cookie policy + origin-scoped jar
lib/cookie-forward.js serverless session persistence via the browser's cookie jar
lib/blocklist.js     tracker domain/endpoint/global-path matching
lib/params.js        tracking query-param stripping
lib/ssrf.js          internal-address guard
lib/stats.js         in-memory telemetry
api/p/[...url].js    Vercel: /p/ proxy function (same pipeline as server.js)
api/stats.js         Vercel: /stats + /stats/reset (per-invocation)
api/_internal.js     Vercel: request/response shape adapters (not a route)
vercel.json          Vercel: URL rewrites (/, /p/, /stats, /fixtures)
config/trackers.json   blocked hosts + endpoints + global paths (incl. $guardian)
config/tracking-params.json  tracking query params
config/tracking-cookies.json tracking cookie names
config/profiles.json   stealth browser identities (chrome-win, firefox-win)
static/index.html    front page (with bookmarklet for the hosted deployment)
test/                node:test unit + integration + serverless suites
```
