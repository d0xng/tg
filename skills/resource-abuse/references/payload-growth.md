# Payload Growth Checks

Use for creation endpoints with user-controlled text fields, such as draft
bodies, comments, profile descriptions, saved filters, titles, notes, report
descriptions, JSON settings, markdown, or HTML-like content.

## Safety

- Use a small growth ladder and stop before the endpoint is stressed.
- Default ladder: normal baseline, 8 KB, 32 KB, 128 KB.
- Do not exceed 256 KB at all without asking d0x directly first. Include the exact
  payload size and the program-policy basis in the approval question.

Bounds: `../../_shared/references/safe-ladder.md` rung 2b (2–3 invocations, own
account, stop on the first sign of shared pressure) plus §B's Step-0 policy gate
in `../SKILL.md`. Do not restate them here.

## Method

1. Create one owned synthetic object with a normal payload and record response
   time, status, object size, and cleanup path.
2. Repeat with 8 KB, 32 KB, then 128 KB in the same field.
3. Use simple deterministic content first: repeated `A`, repeated words, or
   repeated JSON-safe strings.
4. Avoid compression bombs, parser bombs, nested structures, regex backtracking
   payloads, or malformed binary.
5. Measure latency client-side and capture any server-side timing, queue ID,
   object size, validation message, or quota header.
6. Stop as soon as latency grows sharply, the server returns 429/413/4xx limit
   behavior, any 5xx appears, or cleanup becomes uncertain.

## Good Evidence

- no server-side max length on an expensive create endpoint;
- large payload accepted and persisted from a normal user;
- response time grows disproportionately compared with baseline;
- repeated large owned objects are accepted without quota or cooldown;
- downstream processing starts for each large object.

## Not Evidence By Itself

- one large payload accepted with no latency or storage impact;
- client-side max length bypassed while the backend has a reasonable limit;
- high latency caused by the operator's network rather than server processing;
- payloads that require unsafe volume or malformed parser stress to reproduce.
