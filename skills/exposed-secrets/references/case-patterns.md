# Case Patterns — Generalized Technique Shapes

Reusable exposed-secret exploitation shapes: the leak surface, the read-only
replay, and the "converts to <sev> when <condition>" guidance. These are
recognition patterns, not detectors — a matching shape means "prove this class,"
not "it is vulnerable."

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## SaaS/Server Key From JS/Config → API Call → Proven Impact

Pattern:

- a bundle/`.env`/Postman/APK/`.git`/log/backup leaks a server credential —
  Braze `BRAZE_REST_API_KEY`, Google `AIza`, Azure `client_id`+`client_secret`,
  Supabase `sb_secret_`, Stripe `sk_live_`, dotCMS/ES, Zeta, SFMC.

Proof (reach impact):

- identify by prefix/host, call the API read-only, read scopes + one object;
- Braze `/users/export/ids` → PII (Critical when custom-attributes carry
  financial/identity data); Azure `client_credentials` → minted token to
  Management/Vault (Critical when it reaches 20+ services); SSR-cred + Supabase
  signup → thousands of regulated records (converts P1/Critical); Zeta
  GetSubscriber → subscriber PII (High marketing-only, Critical retail/finance).
- full payloads in `saas-key-exploitation.md`. Existence alone = N/A; the API
  call is the deliverable.

## Registered/Anonymous Actor Can Access Bulk PII

Pattern:

- any registered/anonymous actor can access a dataset containing names, emails,
  phones, or other sensitive fields;
- endpoint is not object-specific IDOR but broad data exposure.

Proof:

- one bounded cross-boundary read of one or two redacted records + field names;
- record access state, negative control, and inferred scale;
- do not bulk-export — scale is stated, not exfiltrated.

## Debug Logs Contain Live Tokens/Passwords

Pattern:

- application logs auth/LDAP passwords, bearer tokens, OAuth codes, or reset
  links when debug logging is enabled and the log is exposed.

Proof:

- redacted log snippet + **read-only replay** of the live token/link (mint
  against a non-PII endpoint, or complete a reset link on an account you control,
  then revert). A logged-but-untested secret is not yet a finding.

## Exposed Git Repository

Pattern:

- `.git` metadata is web-accessible;
- source, deleted files, config, or secrets can be reconstructed.

Proof:

- `.git/HEAD` + `.git/config` + targeted object recovery of the secret;
- if the recovered key is live, exercise it via `saas-key-exploitation.md` and
  report at that severity; no bulk clone.

## Local Biometric/Vault Key Exposure

Pattern:

- desktop app stores biometric unlock or vault key material in OS credential
  storage without restrictive ACL/user-presence controls;
- same-user local process can retrieve it and decrypt sensitive vault data.

Safe proof:

- operator-owned vault with synthetic entry;
- source review and local lab extraction;
- no real vault data.

## Exposed Artifact Or Backup

Pattern:

- public backup/archive/export contains config, source, logs, PII, or secrets.

Proof:

- headers/path/size plus redacted minimal snippet;
- when the artifact carries a live credential, exercise it read-only via
  `saas-key-exploitation.md` (or `cloud-exploitation` for AWS/Cognito) and report
  at the proven-impact severity; extract the specific secret, don't bulk-download.
