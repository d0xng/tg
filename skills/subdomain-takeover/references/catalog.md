# Provider catalog — CNAME hint → fingerprint (and what is patched)

The CNAME (or A/NS target) names the **provider**; the HTTP body/status
**confirms the resource is unclaimed**. Match both. A fingerprint alone is a
lead, not a finding — you still owe the **manual claimability** check (bottom of
this file) before claiming. Do NOT run subjack; resolve with `dig`, fingerprint
with `curl`:

```bash
dig +short CNAME sub.target.com
curl -sSL -m 15 -H 'Host: sub.target.com' https://sub.target.com | grep -iF '<fingerprint>'
curl -s -o /dev/null -w '%{http_code}\n' https://sub.target.com
```

## Vulnerable today (CNAME hint → fingerprint string)

A **fingerprint is a provider-specific string in the body.** A bare `NXDOMAIN`,
a bare `404 Not Found`, or a naked status code is *not* a fingerprint — those
rows are marked `unverified` below and cost you a turn unless you first confirm
the provider still hands the name out.

| Provider (CNAME hint) | Fingerprint in body |
|---|---|
| AWS S3 (`*.s3.amazonaws.com`, `*.s3-website-*`) | `The specified bucket does not exist` |
| AWS Elastic Beanstalk (`*.elasticbeanstalk.com`) | no body fingerprint (the EB hostname itself stops resolving) — **unverified — confirm the provider still allows claiming before spending a turn**: the environment name must still be free in that exact region |
| Microsoft Azure (`*.azurewebsites.net`, `*.cloudapp.*`, `*.trafficmanager.net`, `*.blob.core.windows.net`) | no body fingerprint (the Azure resource name itself stops resolving; MSRC calls it "dangling DNS") — **unverified — confirm the provider still allows claiming before spending a turn**: the decisive test is whether that exact resource name is still creatable in your own subscription |
| Bitbucket (`*.bitbucket.io`) | `Repository not found` |
| Campaign Monitor (`createsend.com`) | `Trying to access your account?` |
| Canny (`canny.io`) | `Company Not Found` |
| Cargo Collective (`cargocollective.com`) | bare `404 Not Found` only — **unverified — confirm the provider still allows claiming before spending a turn**: require the provider's own unclaimed-site page plus a signup flow that accepts the custom domain |
| Agile CRM | `Sorry, this page is no longer available.` |
| Anima (`animaapp.io`) | `The page you were looking for does not exist.` |
| Discourse | bare `NXDOMAIN` only — **unverified — confirm the provider still allows claiming before spending a turn**: hosted Discourse sites are provisioned by the vendor, so a free name is rare |
| Gemfury (`*.furyns.com`) | `404: This page could not be found.` |
| GetResponse (`*.gr8.com`) | `With GetResponse Landing Pages, lead generation` |
| Ghost (`*.ghost.io`) | `Site unavailable` |
| HatenaBlog (`hatenablog.com`) | `404 Blog is not found` |
| Help Juice (`*.helpjuice.com`) | `We could not find what you're looking for.` |
| Help Scout (`*.helpscoutdocs.com`) | `No settings were found for this company:` |
| Helprace (`*.helprace.com`) | `HTTP 301` to helprace, no body string — **unverified — confirm the provider still allows claiming before spending a turn** |
| JetBrains YouTrack (`*.myjetbrains.com`) | `is not a registered InCloud YouTrack` |
| LaunchRock (`*.launchrock.com`) | `HTTP 500` from launchrock, no body string — **unverified — confirm the provider still allows claiming before spending a turn** |
| Ngrok (`*.ngrok.io`) | `Tunnel *.ngrok.io not found` |
| Pantheon (`*.pantheonsite.io`) | `404 error unknown site!` |
| Pingdom (`stats.pingdom.com`) | `Sorry, couldn't find the status page` |
| Readme.io (`*.readme.io`) | `The creators of this project are still working` |
| ReadTheDocs (`*.readthedocs.io`) | `The link you have followed or the URL` |
| Short.io (`*.short.io`) | `Link does not exist` |
| SmartJobBoard | `This job board website is either expired` |
| Strikingly (`*.strikinglydns.com`) | `PAGE NOT FOUND.` |
| Surge.sh (`*.surge.sh`) | `project not found` |
| SurveySparrow | `Account not found.` |
| Tilda / Uberflip | `The URL you've accessed does not provide a hub.` |
| UptimeRobot (`stats.uptimerobot.com`) | `page not found` — generic string, so treat as **unverified — confirm the provider still allows claiming before spending a turn**: the status-page slug must still be registerable |
| WordPress.com (`*.wordpress.com`) | `Do you want to register *.wordpress.com?` |
| Worksites | `Hello! Sorry, but the website you're looking` |

The canonical living catalog is EdOverflow's `can-i-take-over-xyz` — cross-check
a provider there for current status and the exact claim procedure. Providers move
between "vulnerable" and "patched" often, which is *why* step 4 (manual
claimability) is mandatory rather than trusting this table.

## Stale-A and NXDOMAIN-apex vectors (not CNAME-based)

- **Stale A record** — the subdomain's A points at a cloud IP the target
  released. If that provider will re-assign the *same* IP to a resource you
  provision (rare on modern EIP pools, feasible on some elastic/ephemeral IP
  services), you inherit the subdomain. Confirm the IP is currently unowned and
  re-assignable before claiming.
- **NXDOMAIN apex** — a CNAME points at `foo.provider.com` whose *base name* is
  itself unregistered. Confirm the base name is genuinely purchasable (registrar
  WHOIS shows available), not merely non-resolving. NXDOMAIN means "nothing
  answers," **never** "you can claim it."

## Patched / edge cases — DO NOT report as takeover without extra proof

These are the classic false positives. A dangling CNAME here is **usually not
claimable** because the provider added domain verification:

- **GitHub Pages** — `There isn't a GitHub Pages site here.` Edge case only;
  org-verified custom domains block re-claim. Needs the exact repo/name free AND
  no org domain verification.
- **Heroku** — `No such app`. Edge case; needs the app name genuinely free with
  no domain verification / ACM.
- **Shopify** — `Sorry, this shop is currently unavailable.` Edge case; requires
  an unclaimed `myshopify` name and no verification.
- **CloudFront** — `ViewerCertificateException` / `The request could not be
  satisfied`. Generally **not** takeoverable; CNAME→CloudFront is usually a dead
  end (alternate-domain + cert binding blocks it).
- **Fastly** — `Fastly error: unknown domain:` — generally **not** takeoverable.
- **AWS ALB** (`Server: awselb`, `NXDOMAIN`) — usually a dead end for takeover.
- **Zendesk** (`Help Center Closed`), **GitLab Pages**, **Statuspage**,
  **Netlify**, **Vercel** — patched / DNS-verification (TXT challenge) required;
  the target controls the challenge, so you cannot claim.

If claiming the resource requires a TXT/DNS token the target owns, it is **not**
a takeover — document it as a dead end in `notes/` and rotate to the next
candidate. NXDOMAIN by itself is never proof.
