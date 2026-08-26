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

## Security notes

- No dependencies, no build step — Node ≥ 18.17 (`fetch`, `node:test`).
- The proxy has **no auth**. It's for personal/local use; don't expose it to
  the open internet without putting something in front of it.
- Don't use it to break a site's terms or the law.

## Layout

```
server.js            entrypoint + routing (resolves the stealth profile)
lib/proxy.js         proxy engine (fetch loop, redirects, responses)
lib/stealth.js       synthesized browser identity + request-kind detection
lib/headers.js       outbound header assembly (stealth on/off)
lib/rewrite.js       HTML URL rewriting + HUD badge
lib/cookies.js       tracking-cookie policy + origin-scoped jar
lib/blocklist.js     tracker domain/endpoint/global-path matching
lib/params.js        tracking query-param stripping
lib/ssrf.js          internal-address guard
lib/stats.js         in-memory telemetry
config/trackers.json   blocked hosts + endpoints + global paths (incl. $guardian)
config/tracking-params.json  tracking query params
config/tracking-cookies.json tracking cookie names
config/profiles.json   stealth browser identities (chrome-win, firefox-win)
static/index.html    front page
test/                node:test unit + integration suites
```
