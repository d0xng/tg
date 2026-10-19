# Source Control Exposure

Use for exposed `.git`, `.svn`, source maps, unminified source, deleted files,
repo metadata, and public source artifacts.

## Method

1. Request minimal metadata first: `.git/HEAD`, `.git/config`, `.git/index`, or
   source map header.
2. Capture status, path, content type, size, and a redacted snippet.
3. Reconstruct the minimum needed to surface a secret — `.git/config` + a few
   pack/objects, or a targeted source map — not the whole repo. Grep the
   reconstructed source **and its history** (deleted/rewritten commits) for
   secret shapes: `AIza`, `sk_live_`, `sb_secret_`, `BRAZE_REST_API_KEY`,
   `client_secret`, `.onmicrosoft.com`, DB/URL creds.

```bash
# .git/HEAD or .git/config returns 200 -> reconstruct the repo (git-dumper is installed)
git-dumper https://<host>/.git/ targets/<program>/notes/gitdump/
cd targets/<program>/notes/gitdump && git log --oneline | head
# the payload is REMOVED secrets — grep history, not just the working tree:
git log -p --all | rg -i 'api[_-]?key|secret|password|token|BEGIN .*PRIVATE KEY' | head -40
```

Keep it targeted: a small repo dumps in seconds, a monorepo does not — if the
dump is large, pull `.git/config` + the specific objects you need instead of the
whole history.
4. **When a live service credential appears, do not stop — pivot to
   `saas-key-exploitation.md` and call the API read-only to prove impact**
   (safe ladder rung 1). The exposed `.git` is the delivery surface; the finding
   is the data/infra the recovered key unlocks.

## Good Evidence

- `.git` metadata is reachable and enough to reconstruct source;
- config reveals remote URLs, internal repo names, deploy paths, or credentials;
- deleted/rewritten commit reveals a secret still valid against its service;
- source contains an API key/token that authenticates when exercised read-only.

## When You Hit Impact

- A recovered key that validates against its service → exploit it via
  `saas-key-exploitation.md`, capture the read-only proof, report at that
  severity.
- Do not bulk-clone large repos or dump full history "to be thorough" — recover
  the specific secret, prove it, and state the rest by inference.
