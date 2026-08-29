// Rewrites HTML so every http(s) URL it references routes back through the
// proxy (/p/<encoded-url>). That is what lets the blocklist, cookie policy and
// header scrubbing apply to sub-resources, and what makes the page same-origin
// so it can render.
//
// Scope (deliberate): HTML attributes + srcset + <base> + meta refresh.
// Inline <script>/<style> content is masked and left untouched — parsing JS
// reliably is a project of its own, and known third-party trackers are caught
// at the network layer instead.

const URL_ATTRS = new Set([
  'src', 'href', 'action', 'poster', 'data', 'xlink:href',
  'data-src', 'data-href', 'data-lazy-src', 'data-lazy-srcset',
  'srcset', 'data-srcset',
]);

const SKIP_PROTOCOLS =
  /^(javascript:|vbscript:|mailto:|tel:|sms:|data:|blob:|about:|ws:|wss:|filesystem:|chrome:|file:)/i;

export function proxyUrlFor(urlString) {
  return '/p/' + encodeURIComponent(urlString);
}

function decodeAttr(v) {
  return v
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&');
}

function encodeAttr(v) {
  return v
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function absolutizeAndProxy(val, base) {
  const v = val.trim();
  if (!v || v.startsWith('#')) return val;
  if (SKIP_PROTOCOLS.test(v)) return val;
  if (v.startsWith('/p/')) return val; // already proxied
  let u;
  try {
    u = new URL(v, base);
  } catch {
    return val;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return val;
  return proxyUrlFor(u.href);
}

function rewriteSrcset(val, base) {
  return val
    .split(',')
    .map((part) => {
      const t = part.trim();
      if (!t) return part;
      const sp = t.search(/\s/);
      const urlPart = sp === -1 ? t : t.slice(0, sp);
      const descriptor = sp === -1 ? '' : t.slice(sp);
      return absolutizeAndProxy(urlPart, base) + descriptor;
    })
    .join(', ');
}

/**
 * Rewrite html (a string) against `baseUrl` (the upstream page URL).
 * Returns { html, counts: { rewritten } }.
 */
export function rewriteHtml(html, baseUrl) {
  const counts = { rewritten: 0 };
  let out = String(html);
  const masked = [];

  const mask = (re) => {
    out = out.replace(re, (m) => {
      masked.push(m);
      return `\x00VM${masked.length - 1}\x00`;
    });
  };

  // Mask regions where the attribute regex would corrupt content:
  // script BODIES (the opening tag stays — its src attribute must be
  // rewritten), styles, RCDATA elements, and comments.
  out = out.replace(/(<script\b[^>]*>)([\s\S]*?)(<\/script>)/gi, (m, open, body, close) => {
    masked.push(body);
    return open + `\x00VM${masked.length - 1}\x00` + close;
  });
  mask(/<style\b[^>]*>[\s\S]*?<\/style>/gi);
  mask(/<textarea\b[^>]*>[\s\S]*?<\/textarea>/gi);
  mask(/<title\b[^>]*>[\s\S]*?<\/title>/gi);
  mask(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi);
  mask(/<!--[\s\S]*?-->/g);

  // 1) <base href> — a base tag re-points ALL relative resolution, so compute
  // the effective base before rewriting anything.
  let effectiveBase = baseUrl;
  const baseTag = out.match(/<base\b[^>]*>/i);
  if (baseTag) {
    const href = baseTag[0].match(/href\s*=\s*["']([\s\S]*?)["']/i);
    if (href) {
      try {
        effectiveBase = new URL(decodeAttr(href[1]), baseUrl).href;
      } catch {
        /* keep page URL as base */
      }
    }
  }
  out = out.replace(/<base\b[^>]*>/gi, (m) =>
    m.replace(/(href\s*=\s*)(["'])([\s\S]*?)\2/gi, (mm, pre, q, val) => {
      const nv = absolutizeAndProxy(decodeAttr(val), baseUrl);
      if (nv.startsWith('/p/') && !val.startsWith('/p/')) counts.rewritten++;
      return pre + q + encodeAttr(nv) + q;
    })
  );

  // 2) <meta http-equiv="refresh" content="0; url=...">
  out = out.replace(/<meta\b[^>]*>/gi, (m) => {
    if (!/http-equiv\s*=\s*["']?\s*refresh/i.test(m)) return m;
    return m.replace(/(content\s*=\s*)(["'])([\s\S]*?)\2/gi, (mm, pre, q, val) => {
      const dec = decodeAttr(val);
      const m2 = dec.match(/^(\s*(?:\d+(?:\.\d+)?\s*;\s*)?url\s*=\s*)(.*)$/i);
      if (!m2) return mm;
      const nv = absolutizeAndProxy(m2[2].trim(), effectiveBase);
      if (nv.startsWith('/p/') && !val.startsWith('/p/')) counts.rewritten++;
      return pre + q + encodeAttr(m2[1] + nv) + q;
    });
  });

  // 3) Generic URL attributes.
  out = out.replace(/([a-zA-Z][\w.:-]*)(\s*=\s*)(["'])([\s\S]*?)\3/g, (m, name, eq, q, val) => {
    const n = name.toLowerCase();
    if (!URL_ATTRS.has(n)) return m;
    const dec = decodeAttr(val);
    const nv =
      n === 'srcset' || n === 'data-srcset'
        ? rewriteSrcset(dec, effectiveBase)
        : absolutizeAndProxy(dec, effectiveBase);
    if (nv.includes('/p/') && !val.includes('/p/')) counts.rewritten++;
    return name + eq + q + encodeAttr(nv) + q;
  });

  // Restore masked regions verbatim.
  out = out.replace(/\x00VM(\d+)\x00/g, (_, i) => masked[Number(i)]);

  return { html: out, counts };
}

/**
 * Inject a small fixed badge showing the page is being viewed through Veil.
 */
export function injectHud(html, { host, rewritten, blockedTotal }) {
  const badge = `<div id="veil-hud" style="position:fixed;top:8px;right:8px;z-index:2147483647;display:flex;gap:8px;align-items:center;background:rgba(8,10,14,.9);color:#aebfd4;border:1px solid #26324d;border-radius:999px;padding:5px 12px;font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;backdrop-filter:blur(8px);box-shadow:0 4px 24px rgba(0,0,0,.4)" title="Viewed through Veil, an anti-tracking proxy. Click to hide.">
<span>\u{1F6E1} <b style="color:#7fd1ff">veil</b></span>
<span style="opacity:.5">|</span>
<span>${escapeHtml(host)}</span>
<span title="URLs rewritten to route through the proxy">${rewritten} routed</span>
<span title="Tracker requests blocked since this proxy started">${blockedTotal} trackers blocked</span>
<a href="/" title="Veil home" style="color:#7fd1ff;text-decoration:none;margin-left:2px">\u2302</a>
</div>
<script>(function(){var e=document.getElementById('veil-hud');if(!e)return;e.addEventListener('click',function(ev){if(ev.target.tagName!=='A'){e.remove();}});})();</script>`;
  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, badge + '\n</body>');
  return html + '\n' + badge;
}
