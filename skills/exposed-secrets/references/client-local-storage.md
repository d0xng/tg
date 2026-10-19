# Client And Local Secret Storage

Use for desktop/mobile/browser storage of sensitive material: vault keys,
biometric keys, refresh tokens, session cookies, API tokens, local databases,
credential manager entries, and keychain/keystore misuse.

## Method

1. Determine threat model: same local user, malicious app, physical access,
   sandbox escape, backup extraction, or rooted/jailbroken device.
2. Prefer source review and local lab reproduction.
3. Use only operator-owned device/account/vault (this IS the own-context proof —
   safe ladder rung 2).
4. **Actually retrieve the secret to prove impact** — extract the real
   token/vault-key/refresh-token from YOUR OWN account/device with the
   unprivileged same-user process, and show it decrypts your test vault item or
   authenticates against the backend. Retrieval + use is the finding; "the store
   looks weak" is not.
5. Do not collect another real user's vault or credentials.

## Good Evidence

- same-user unprivileged process can retrieve vault/biometric key material;
- token stored unencrypted or with predictable key;
- credential manager/keychain item lacks expected ACL or user-presence control;
- local database contains recoverable secrets after logout/lock.

## False Positive Gates

- OS design intentionally allows same-user access and no sensitive app secret is
  recoverable;
- attacker already needs admin/root and no extra impact is shown;
- only non-sensitive preferences are exposed.
