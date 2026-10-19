---
name: deserialization-hunting
description: "Hunt unsafe deserialization and signed-state forgery across Java, .NET, PHP, Python, Node, Ruby, and framework-specific formats. Use when a request contains a serialized or base64-like blob, known serialization marker, class or assembly error, ViewState, remember-me or SSO state, import/export or job payload, or a leaked signing key. Prefer a non-destructive oracle and route confirmed code execution to `rce-hunting`."
---

# Deserialization Hunting

Unsafe deserialization is a trust-boundary failure: attacker-controlled bytes are
turned back into live objects, framework state, jobs, templates, or claims
**before** authentication, integrity, type, and schema checks. It is one of the
few classes that reaches unauthenticated **RCE** directly — that is the payable
target here, and this skill exists to reach it, not to observe it.

## Mission

Take user-controllable serialized data across the deserialization boundary and
**prove RCE, auth bypass, or cross-tenant impact** with the safest evidence that
still proves it. Discovery is rung 0. A decoded blob, a marker, a version banner —
none of those are a finding. The finding is the proven impact. Do not stop at
"this looks like base64" or "the parser is reachable"; climb to `id`.

Payable impact, in priority order:

1. **Unauthenticated RCE** — the ceiling. Benign command output (`id`, `whoami`,
   `hostname`) or an OOB DNS/HTTP callback proving code executed.
2. **Auth bypass / ATO via forged signed state** — forge a session/ViewState/
   rememberMe/JWT with a leaked or known-default key and become admin/another user.
3. **Cross-tenant / privesc via tampered unsigned state** — flip an owned object's
   `role`/`tenant`/`id` field and cross a boundary.
4. **Type-confusion / class-load reachability** proven with a DNS-only gadget when
   a full command PoC is unsafe on prod (state prod-equivalent impact by inference).

## Doctrine — read this before the old instincts kick in

This skill was previously mis-calibrated toward timidity. The three fixes below
override any "stop / observe / hand off" instinct you carry:

- **A benign command IS the proof, not a banned payload.** `id`, `whoami`,
  `hostname`, `uname -a`, `cat /etc/hostname` are read-only, non-destructive, and
  are exactly what the program wants to see. Run them. What is banned is reverse
  shells, persistence, `rm`/file writes to real paths, credential dumping of other
  tenants, network pivoting, and **DoS/parser-bomb payloads** — never the `id` that
  proves the class. (Safe ladder rung 1-2.)
- **The 500-with-error-body IS the positive oracle — do NOT "stop on 5xx".** The
  single most common miscalibration: bailing on the exact 500 that confirms the top
  CVE. A Next.js RSC `500` whose body is `{"a":"$@1",...}`, a `.NET` type-resolution
  error naming an assembly, a Java `ClassNotFoundException`/`InvalidClassException`,
  a PHP `unserialize()` warning, a JSF `ViewExpiredException` — each of these is the
  server telling you it deserialized your bytes **before** validating them. Capture
  the body, diff it against the benign baseline, and proceed. The only 5xx you stop
  on is a repeated worker-restart / retry-storm shape, and you get there only by
  never SENDING a DoS payload in the first place.
- **Forging with a LEAKED or KNOWN-DEFAULT key IS the exploit — only brute-forcing
  is out.** If a signing/encryption key is exposed (JS bundle, `.env`, debug page,
  GitHub, source map) or is a documented hardcoded default (Shiro
  `kPH+bIxk5D2deZiIxcaaaA==`, Exchange ViewState `CB2721ABDAF8E9DC...`, Telerik
  default key, Rails dev-mode secret), **forge the token and prove impact** — that
  is the deliverable. Do not "hand a leaked key to exposed-secrets and stop." What
  is out is **online brute-forcing** of an unknown key against prod; cracking your
  OWN token offline with `hashcat`/`flask-unsign --wordlist` is fine.

Every "keep it passive / prefer staging / do not run RCE / stop on 5xx / hand off
the key" phrasing from the prior version is dead. The governing rule is the shared
safe ladder, not passivity.

## Import — shared foundation (read once per session)

- `../_shared/references/safe-ladder.md` — the read-only -> own/anon -> minimal ->
  UAT -> reach-impact ladder that governs *how far* to climb. Climb until impact is
  proven; stop one rung below proof and you have failed.
- `../_shared/references/public-by-default-keys.md` — before you call a leaked key
  a finding, resolve SKIP vs PURSUE. A leaked **signing/encryption** key (APP_KEY,
  SECRET_KEY, machineKey, secret_key_base) is always PURSUE here — it forges auth.

## Read-On-Demand References

Load only the reference matching the fingerprint:

- `references/java.md` — ysoserial gadget selection, URLDNS safe oracle, Struts2
  OGNL, Shiro rememberMe (default-key forge), WebLogic T3/XMLDecoder, Fastjson/
  Jackson polymorphic typing, Log4Shell, JSF ViewState, SnakeYAML.
- `references/dotnet.md` — ysoserial.net, ViewState MAC oracle + machineKey forge
  (CVE-2020-0688 Exchange), Telerik RadAsyncUpload, JSON.NET `TypeNameHandling`,
  BinaryFormatter/LosFormatter.
- `references/php.md` — phpggc chains (Laravel/Symfony/Monolog/Guzzle), PHAR
  polyglot upload, Laravel APP_KEY decrypt+forge (CVE-2018-15133).
- `references/python.md` — pickle RCE, PyYAML `!!python/object/apply`, flask-unsign
  decode/sign, Django SECRET_KEY + PickleSerializer.
- `references/node-ruby.md` — node-serialize `_$$ND_FUNC$$_`, prototype-pollution
  gadgets, Ruby Marshal universal gadget, Rails secret_key_base cookie forge,
  YAML `!ruby/object`.
- `references/leaked-key-forge.md` — the cross-cutting leaked-key -> forge ladder:
  where each key leaks, how to identify it, the exact forge command, and the
  proven-impact target for Rails / Laravel / Flask / Django / ASP.NET / JWT / Shiro.
- `references/case-patterns.md` — converted-report shapes and the DNS-only oracles.
- `../_shared/references/output-contract.md` — where results go: the notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim` dedup key, and the severity enum.
- `../_shared/references/tooling.md` — what is installed on this host, what is not, and the install line for each missing binary. **Most of this class depends on binaries this laptop does not ship** (`ysoserial`, `phpggc`, `flask-unsign`, `jwt_tool`) — read it before you plan a proof.
- `../_shared/references/nextjs-rsc-deser.md` — **shared with rce-hunting** —
  Next.js RSC CVE-2025-55182 (unauth RCE) / CVE-2025-55184 (DoS): the 2-step 404/
  500 probe and the child_process payload. Single canonical copy; do not duplicate.

## Triggers

Fire when any of these appear in requests, responses, JS, mobile traffic, source,
errors, or storage:

- base64-like blobs in cookies, headers, hidden inputs, query/body params, JSON
  fields, multipart fields, websocket messages, or queue payloads;
- magic markers: `rO0`, `aced0005` (Java), `AAEAAAD` (BinaryFormatter), `/wE`
  (ViewState), `O:`, `a:`, `s:`, `i:` (PHP serialize), `gA[JNSW]`, `\x80[\x02-\x05]`
  (pickle proto 2/3/4/5 — `gAS` alone misses proto 2, 3 and 5),
  `BAh` (Ruby Marshal), `__type`, `$type`, `@type`, `@class`, `!!python/object`,
  `!ruby/object`, `_$$ND_FUNC$$_`, `py/object`;
- Next.js RSC: `x-powered-by: Next.js`, `content-type: text/x-component`,
  `vary: RSC, Next-Router-State-Tree`, `Next-Action` handling;
- errors naming classes/assemblies/namespaces, invalid MAC, invalid ViewState,
  `unserialize()`, `UnpicklingError`, `Psych`, `ClassNotFoundException`,
  `InvalidClassException`, `ViewStateException`, `autoType is not support`,
  JNDI/LDAP lookups;
- import/export, backup/restore, saved workflow/draft, remember-me, SSO relay,
  webhook, integration, report template, cart/session, scheduler/job features;
- ViewState (`__VIEWSTATE`), JSF (`javax.faces.ViewState`), Struts params, Shiro
  `rememberMe`, Spring session, AMF/Hessian/T3/IIOP endpoints;
- filesystem/URL fields later passed to file-metadata functions, archive handlers,
  image/doc processors, or connector/JNDI/LDAP configuration;
- a leaked signing/encryption key (APP_KEY, SECRET_KEY, machineKey,
  secret_key_base, a Shiro/Telerik default key) — go straight to forge.

## Detection oracles — rung 1, code-execution-free

Before any command payload, confirm the boundary with a **DNS/HTTP callback or an
error differential** — zero code execution, fully non-destructive, and it is often
enough to make the finding real:

- **Java native**: `java -jar ~/tools/ysoserial.jar URLDNS http://<id>.oob` — triggers
  a DNS lookup only. A hit proves attacker bytes hit `readObject()`. No gadget, no
  exec. (`ysoserial` is not installed here — see `references/java.md` for the install
  line; the error-differential oracle below needs nothing.)
- **Fastjson/Jackson**: `{"@type":"java.net.Inet4Address","val":"<id>.oob"}` (or
  `java.net.URL`) — DNS callback confirms autoType/default-typing without a gadget.
- **Log4Shell**: `${jndi:dns://<id>.oob/x}` in any logged field (User-Agent,
  X-Api-Version, username) — DNS/LDAP callback = confirmed, no code exec needed.
- **Shiro**: send `rememberMe=invalid`; a `Set-Cookie: rememberMe=deleteMe`
  response fingerprints Shiro (then default-key forge, see `references/java.md`).
- **ViewState**: corrupt the trailing MAC bytes. `500 Validation of viewstate MAC
  failed` = MAC on (need the key); silent accept = MAC off, forge freely.
- **Next.js RSC**: the 404-then-500 two-step probe in the shared reference — the
  `500` with an RSC body is the positive oracle.
- **PHP/Python/Ruby**: one-byte corruption of an owned blob → an `unserialize()`
  warning / `UnpicklingError` / `Psych::` / class-name error differential proves
  server-side deserialization of your input.

Use `interactsh-client`, a Burp/Caido Collaborator, or `canarytokens.org` as the
OOB listener. Getting the callback is the confirm; the benign command is the
escalation.

## Algorithm

1. **Map the candidate.** Endpoint, parameter/cookie/header/field, transport, auth
   state, object owner, content type, encoding layers, observed marker.
2. **Decode.** URL-decode, base64/base64url, gzip/deflate, JSON unescape, hex,
   framework wrapping — until you see the serialization structure.
3. **Fingerprint the runtime** from markers, errors, headers, dependency files, JS
   routes, source leaks. Load the matching platform reference.
4. **Check integrity.** Unsigned / MACed / encrypted / session-bound / server-side
   opaque? If a key is leaked or a known default applies → jump to
   `references/leaked-key-forge.md` and forge.
5. **Fire the rung-1 oracle** (DNS-only gadget or error differential above). A hit
   proves the boundary with zero code execution.
6. **Escalate to a benign command.** Pick the gadget for the classpath
   (`references/java.md` / `dotnet.md` / `php.md` / `python.md` / `node-ruby.md`),
   run `id`/`whoami`, capture
   output. On the 500-with-error-body path, that error body IS the confirm — don't
   bail. This is the payable proof.
7. **For signed state**: forge the session/ViewState/rememberMe/JWT with the leaked
   or default key and demonstrate admin/other-user access (own-account target on
   prod; full cross-tenant on UAT per the safe ladder).
8. **Dedup before you call it new:** `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle. Also check this session's `targets/<program>/findings/`.
9. **Validate** with the `validation` skill, then `report-writing`. Write the lead
   itself to `targets/<program>/leads/` in the format in
   `../_shared/references/output-contract.md`.

## Leaked-key -> forge ladder (summary; full detail in the reference)

The instant a signing/encryption key is exposed OR a known-default applies, the
finding is auth-bypass/RCE by forging — this is one of the highest-converting
paths in the class:

| Runtime | Key | Forge target | Tool |
|---|---|---|---|
| Rails | `secret_key_base` (`credentials.yml.enc`, env, `secrets.yml`) | signed/encrypted `_session` cookie -> Marshal gadget = RCE | `ActiveSupport::MessageEncryptor`, rails-doubletap |
| Laravel | `APP_KEY` (`.env`, debug page, GitHub) | encrypted cookie -> phpggc `Laravel/RCE*` = RCE (CVE-2018-15133) | laravel-crypto-killer + phpggc |
| Flask | `SECRET_KEY` | session cookie forge; pickle serializer -> RCE | `flask-unsign --sign` |
| Django | `SECRET_KEY` (`settings.py`, debug page) | signed session; `PickleSerializer` -> RCE | `django.core.signing` |
| ASP.NET | `machineKey` (validation+decryption; web.config/source leak; Exchange default) | forge `__VIEWSTATE` -> RCE (CVE-2020-0688) | `ysoserial.net -p ViewState` |
| Shiro | rememberMe key (default `kPH+bIxk5D2deZiIxcaaaA==` or leaked) | AES-encrypt a ysoserial gadget -> RCE (CVE-2016-4437) | ysoserial + AES-CBC |
| Telerik | `DialogParametersEncryptionKey` (default/leaked) | RadAsyncUpload deser -> RCE (CVE-2019-18935) | ysoserial.net + Telerik crypto |
| JWT | HMAC secret (leaked/weak) or RS256->HS256 confusion | forge admin/other-user claims | `jwt_tool`, hashcat -m 16500 (own token, offline) |

Brute-forcing an **unknown** key online against prod is the only banned move.
Forging with a leaked/default key, or cracking your **own** token offline, is the
exploit — do it.

**Nothing in the Tool column ships on this laptop** — the binaries (`ysoserial`,
`ysoserial.net`, `phpggc`, `flask-unsign`, `jwt_tool`, `hashcat`) are absent, and
the library entries (`ActiveSupport::MessageEncryptor`, `django.core.signing`) need
their gem/package. The *runtimes* are present — `java`, `php`, `ruby`, `python3`,
`pipx` — so each is a single install away; the exact lines are in
`../_shared/references/tooling.md` and inline in each platform reference. Install
it; do not downgrade the finding because a binary was missing. The oracles (MAC
diff, `rememberMe=deleteMe`, `type=rau`, byte-flip errors, cookie decode) are pure
`curl`/`python3` and need nothing — fire those first.

## Safe ladder in this class (recalibrated)

- **Rung 1 (read-only):** DNS-only gadget hit, benign command output (`id`),
  scope read-back of a forged token. Almost every proof lives here.
- **Rung 2 (own/anon):** forge a session for an account **you** created; run the
  command in the app's own worker context; poison a cache key you can write.
- **Rung 3 (prove the scale):** one command, one forged token, one cross-object read. Never
  bulk-dump other tenants' data to "show scale" — state scale by inference.
- **Rung 4 (UAT):** if RoE restricts RCE/cross-tenant proof to `*-uat`/`*-oat`, run
  the full command/forge there; on prod stop at the DNS-oracle + benign non-PII read
  and state prod-equivalent impact.
- **Rung 5 (not attempted — d0x's approval before execution):** writing to real files, other-tenant data on prod,
  anything beyond a benign read-only command. Bring the exact payload.

## Dedup note

The **technique** is reusable across targets; a specific report already submitted
is CLOSED on that target — do not re-discover it there. Next.js RSC and
Ghost/Strapi CVEs are mass-exploited: **be first or skip**.

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## Severity

- **critical**: unauth RCE (benign command output / OOB from an unauth request),
  ATO via forged signed state, tenant escape.
- **high**: authenticated RCE in a bounded worker, forged-session privesc, dangerous
  type-confusion reaching a proven sink, cross-account state tamper.
- **medium**: unsigned/tamperable state with account-local impact, class/type
  disclosure proving a risky parser is reachable but not yet exploited.
- **info/low**: fingerprint only, no boundary crossed — keep hunting, this is not a
  stopping point.

## Evidence policy — what to capture, what to redact

Raw proof (decoded blobs, the gadget payload, OOB-listener logs, forged tokens,
command output) goes under `targets/<program>/notes/` while it is raw, and moves to
`targets/<program>/findings/` once it is a proven bug. Redact victim PII; keep
object/table ids in `id=<n>` form, and keep runtime version/build strings — those
are the impact. **Flag every signing key you forged with for rotation.**

Capture all of these before writing the lead:

- the exact parameter / cookie / header / upload-field / message location;
- the runtime + CVE fingerprint (redact the secret itself, keep the version);
- every decoding layer you peeled (URL, base64/base64url, gzip, hex, framework wrap);
- the integrity result: unsigned / MACed / encrypted / session-bound / **leaked or
  known-default key** — name which;
- **the rung-1 oracle that fired**: the DNS-only gadget hit, the `${jndi:dns}`
  callback, the `500`-with-error-body, the MAC-failure diff, the byte-flip parser
  error;
- **the proof**: benign command output (`id`/`whoami`), the OOB callback id, or the
  forged token accepted (`/me` returns the forged identity);
- the negative control: the unmodified blob behaves normally, a benign sibling value
  does not fire, a corrupted-but-valid-MAC blob is rejected;
- if RoE forced the command or cross-tenant proof to UAT, say so and state the
  prod-equivalent by inference.

Title the lead by runtime/CVE + boundary and keep the string STABLE across sessions
(the dedup key is `primitive|host|claim`): `Next.js RSC RCE on www.<host>`,
`Shiro default-key RCE`, `ViewState CVE-2020-0688` — never "deserialization bug".
Do not inflate a marker-only or DNS-oracle-only proof to critical without the
command, the callback, or a stated UAT-proven prod equivalent.

**Scope is a safety boundary, not a hunting filter.** Only the **dial target** is
gated — the app host serving the serialized endpoint, the WebLogic T3 `:7001` port,
the OWA path must be one the program authorized. Payload *values* are never scoped:
the OOB listener domain, a leaked key inside a forged cookie, an `ldap://`/`jndi:`
URL inside a gadget, the gadget bytes themselves. The callback landing on **your**
listener is not a scope question — that host is yours. If the leak came from an
authorized asset but the vulnerable service host is not in scope, surface the chain
rather than dialing it.

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- `exposed-secrets`: a leaked key you found here that is NOT a signing key (API/
  service key) — but a signing key you FORGE here yourself, don't hand off.
- `cloud-exploitation`: the RCE lands you on IMDS/service creds or a cloud role.
- `js-source-to-sink`: JS bundles leak serialized routes, keys, or type maps.
- `idor-bola` / `tenant-isolation`: tampered serialized state exposes another tenant.
- `resource-abuse`: a genuine parser-cost/DoS shape (never SEND the DoS payload).
- `rce-hunting`: the execution sink is command/template/upload, not object deser
  (shares `../_shared/references/nextjs-rsc-deser.md` with this skill).
- `validation`: every high/critical claim before `report-writing`.
