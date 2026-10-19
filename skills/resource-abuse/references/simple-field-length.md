# Simple Field Length Checks

Use for fields developers often treat as harmless but route through validation,
normalization, lookup, email, search, or uniqueness checks.

Examples:

- email;
- username;
- display name;
- slug;
- phone;
- address;
- invitee;
- recipient;
- webhook URL.

Bounds: `../../_shared/references/safe-ladder.md` rung 2b (2–3 invocations, own
account, stop on the first sign of shared pressure) plus §B's Step-0 policy gate
in `../SKILL.md`. Do not restate them here.

## Method

1. Test only with the operator account, registration sandbox, or owned profile.
2. Send one baseline valid value.
3. Send one oversized but syntactically simple value, capped at the payload
   ladder in `payload-growth.md`.
4. Record whether the server rejects early with a clear max-length error or
   processes slowly, queues work, normalizes repeatedly, or returns 5xx.
5. Stop after the first clear signal.

## Good Evidence

- missing server-side max length on a field used in expensive validation;
- slow uniqueness/search/email-normalization path from one oversized value;
- 5xx or timeout from one owned request where a clean 4xx limit was expected.

## Not Evidence By Itself

- client-side limit bypass when backend rejects cleanly;
- one oversized value accepted but not persisted or processed;
- latency caused by local network variance.
