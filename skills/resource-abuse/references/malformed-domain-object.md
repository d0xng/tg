# Malformed Domain Object Checks

Use for APIs that parse encoded blobs, serialized objects, block/header payloads,
import files, signed envelopes, or protocol-specific messages.

## Safety

- Prefer static analysis or local/staging reproduction of the parser path.
- On live production, send at most one request only when policy permits and the
  target action is owned/reversible.
- Treat a connection reset, worker restart signal, repeated retry, or 5xx from a
  single malformed object as a high-risk lead for validation review, not as a
  reason to retry.

Bounds: `../../_shared/references/safe-ladder.md` rung 2b (2–3 invocations, own
account, stop on the first sign of shared pressure) plus §B's Step-0 policy gate
in `../SKILL.md`. Do not restate them here.

## Method

1. Identify the parser path and normal valid object.
2. Build the smallest malformed object that violates one invariant, such as
   length, missing field, wrong encoding, impossible enum, or invalid checksum.
3. Send at most one controlled production probe when allowed.
4. Capture response, parser errors, retry behavior, queue IDs, and whether the
   system returns clean validation or fatal behavior.
5. Stop immediately on crash-like behavior.

## Good Evidence

- one malformed owned object reaches a fatal path instead of a clean validation
  error;
- local/staging proof shows process exit or worker crash from an untrusted
  field;
- production shows a single controlled 5xx/reset matching source-level or local
  evidence.

## Not Evidence By Itself

- generic 400/422 validation;
- repeated malformed probes;
- impact requiring high volume, parser bombs, or destructive object graphs.
