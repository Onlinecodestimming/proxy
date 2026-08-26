# 🛡 veil — anti-tracking web proxy

A zero-dependency Node.js proxy that scrubs the web before it reaches you. Point your
browser at it, enter any URL, and every hop is sanitized:

```
browser ──▶ /p/<urlencoded-url> ──▶ veil ──▶ upstream site
              │  strip tracking params
              │  refuse known tracker domains (never even fetched)
              │  scrub fingerprint/context headers, drop leaking referrers
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

| Env var                | Default | Meaning                                              |
| ---------------------- | ------- | ---------------------------------------------------- |
| `PORT` / `HOST`        | `3000` / `0.0.0.0` | bind address                                  |
| `VEIL_USER_AGENT`      | *(client's)* | force one outgoing User-Agent                    |
| `VEIL_ACCEPT_LANGUAGE` | *(client's)* | force one outgoing Accept-Language               |
| `VEIL_ALLOW_LOOPBACK`  | off     | permit `127.0.0.0/8`/`::1` targets (for local testing) |

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
- **Fingerprint & context headers** — `Sec-Ch-Ua*` client hints, `sec-fetch-*`,
  `Origin` are dropped; `Referer` is replaced by the upstream site's own bare
  origin; `DNT: 1` + `Referrer-Policy: no-referrer` are sent
- **HTML rewriting** — `src`/`href`/`action`/`poster`/`data-src`/`srcset`/`<base>`/
  meta-refresh all re-anchor through the proxy so the policies above apply to
  sub-resources and the page renders same-origin. `X-Frame-Options` and CSP
  `frame-ancestors` are dropped so the page actually displays
- **SSRF guard** — loopback, RFC1918, CGNAT, link-local (cloud metadata!), and
  reserved ranges are refused, including via DNS answers

Telemetry (all in-memory, nothing written to disk): `GET /stats`, reset with
`GET /stats/reset`. The front page shows live counters and a "recently blocked"
feed.

## Endpoints

| Path             | Purpose                                    |
| ---------------- | ------------------------------------------ |
| `/`              | front page                                 |
| `/p/<urlencoded-url>` | proxy target (how all rewriting works) |
| `/stats`         | JSON counters + recent blocks              |
| `/stats/reset`   | zero the counters                          |

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
- hide the proxy's own egress IP or TLS metadata,
- route upstream through an HTTP(S) egress proxy (outbound goes direct;
  in a restricted network the proxy sees what the host can reach).

Treat it as "a lot less tracking", not "no tracking".

## Security notes

- No dependencies, no build step — Node ≥ 18.17 (`fetch`, `node:test`).
- The proxy has **no auth**. It's for personal/local use; don't expose it to
  the open internet without putting something in front of it.
- Don't use it to break a site's terms or the law.

## Layout

```
server.js            entrypoint + routing
lib/proxy.js         proxy engine (fetch loop, redirects, responses)
lib/rewrite.js       HTML URL rewriting + HUD badge
lib/headers.js       outbound header scrubbing
lib/cookies.js       tracking-cookie policy + origin-scoped jar
lib/blocklist.js     tracker domain/endpoint matching
lib/params.js        tracking query-param stripping
lib/ssrf.js          internal-address guard
lib/stats.js         in-memory telemetry
config/*.json        all the "knowledge" — edit to taste
static/index.html    front page
test/                node:test unit + integration suites
```
