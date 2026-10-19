# Logs And Debug Exposure

Use for logs, debug output, stack traces, request dumps, auth logs, LDAP/OAuth
logs, and verbose application diagnostics.

## Method

1. Identify log source and access state.
2. Capture minimal redacted snippet showing sensitive field names and the live
   token/password/reset-link.
3. Record environment, log level, timestamp, affected component, and whether the
   log is public or role-restricted incorrectly.
4. Do not download full logs — grep for the live secret and stop.
5. **Exercise a live secret read-only to prove impact.** A logged bearer token,
   API key, session cookie, OAuth code, or reset link that still authenticates is
   the finding — not the log line. Mint/replay it against a non-PII endpoint or
   your own session (safe ladder rung 1), or, for a reset/magic link, complete it
   on **an account you control** to prove takeover, then revert. If it maps to a
   service in `saas-key-exploitation.md`, call that API. A logged-but-untested
   token is rung 0, not a finding.

## High-Value Patterns

- LDAP/user password logged in plaintext at debug level;
- OAuth/SAML tokens or authorization codes logged;
- reset links or magic-login links logged;
- session cookies, bearer tokens, API keys, webhook secrets in request logs;
- stack traces reveal private paths, config, secrets, or internal services.

## Good Evidence

- log contains a secret that **authenticates when exercised** read-only;
- affected versions/config explain why logging occurs;
- access state proves an unintended actor can read the log;
- redacted snippet + the read-only proof (scopes/response) the token unlocked.
