# Web Cache Poisoning / Denial Checks

Use when CDN/cache behavior can turn one crafted request into persisted denial
of access, wrong content, wrong object, or a broken static asset.

## Common Patterns

- cache and origin normalize paths differently, especially slash vs backslash,
  duplicate slashes, dot segments, encoded slashes, mixed case, or trailing
  delimiters;
- cache key ignores a header/query/path component that origin uses for routing;
- origin-generated `404`, `403`, `5xx`, redirect, empty body, or wrong object is
  cached for the canonical URL;
- forwarded or host-like headers influence generated links, redirects, CORS, or
  asset URLs but are not part of the cache key;
- CDN assets, images, scripts, CSS, documentation pages, product widgets, or
  marketplace/add-on assets can be made unavailable through a poisoned variant.

## Safety

- Use a unique nonce, low-traffic test path, owned shop/page/resource, or
  harmless static asset variant.
- Never poison a popular production URL, login flow, checkout flow, public docs
  homepage, or shared CDN asset at all — that requires d0x's approval before execution.
- Use one crafted variant at a time.
- Stop immediately if a shared URL returns the poisoned response, if TTL is
  unclear, or if remediation/purge would require vendor action.

Bounds: rung 2b of `../../_shared/references/safe-ladder.md` (2–3 invocations, own
account, stop on the first sign of shared pressure) applies **only on a nonce or
owned path**. Any variant that could land in a **shared cache entry** — a canonical
URL, a CDN asset, anything a real user would be served — is **rung 5: not attempted —
ask d0x directly before executing**, which is the rung
`../../tenant-isolation/references/cache-deception.md` (the owner of the sibling
deception class) assigns to every poisoning proof. §B's Step-0 policy gate in
`../SKILL.md` applies on top. Do not restate either here.

If what you land is an **authenticated page sitting in a public cache entry**
(anonymous, cookie-less request returns another user's page), that is web cache
**deception**, not denial — it is a data-disclosure finding owned by
`../../tenant-isolation/references/cache-deception.md`. Stop here and run that file;
it holds the `X-Cache` MISS-then-HIT / climbing-`Age` proof and the severity anchors.

## Method

1. Choose a low-impact URL: owned page, test store, cache-busted nonce path, or
   harmless static resource.
2. Record baseline with cache headers: `Cache-Control`, `Age`, `ETag`, `Vary`,
   `X-Cache`, CDN-specific headers, status, body hash, and canonical URL.
3. Send one crafted variant that changes only one suspected cache-key dimension:
   path normalization, encoded segment, benign query param, or one harmless
   header.
4. Re-request the canonical URL once or twice from the same unauthenticated
   state and compare status/body/cache headers.
5. Capture enough evidence for validation: baseline, poison request, canonical
   re-request, cache header deltas, affected asset type, and estimated blast
   radius.

## Good Evidence

- canonical URL serves cached error/wrong body after one crafted variant;
- static resource becomes unavailable or wrong-content cached without auth;
- cache `Age`/`X-Cache` proves the poisoned response is served from cache;
- mismatch is isolated to a cache-key/origin-routing disagreement;
- impact affects many tenants/pages/assets from one cacheable primitive, proven
  on a safe low-traffic resource.

## Not Evidence By Itself

- one uncached 404/500;
- response varies only for the crafted URL, not canonical cache hits;
- cache includes the tested header/query/path component correctly;
- proof requires repeated requests or broad poisoning attempts;
- only the tester's browser cache is affected.
