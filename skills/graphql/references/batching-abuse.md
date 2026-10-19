# Batching — N operations, one HTTP request

Rate limiters, WAF request counters, lockout counters, per-request CSRF checks and
audit trails all reason in units of **HTTP requests**. A GraphQL document holds an
unbounded number of operations. That mismatch is the primitive, and it is the one
genuinely GraphQL-specific thing in the authentication and enumeration space.

## Contents

- The two batching forms
- What it actually buys you
- The finding is the broken counting model — and how to prove it
- Where the rig's rules bind
- Uses that are not brute force
- Controls that stop it
- The DoS families — recognize, never fire

## The two batching forms

**Alias batching** renames each field's response key so the same field can appear
many times in one operation. It is defined in the GraphQL specification, so it
works essentially everywhere:

```graphql
mutation {
  a1: login(username: "u1", password: "p1") { accessToken }
  a2: login(username: "u1", password: "p2") { accessToken }
  a3: login(username: "u2", password: "p1") { accessToken }
}
```

Each alias returns independently: successes land in `data.<alias>`, failures land
in `errors[]` with `path: ["<alias>"]`. **That per-alias `path` is what makes the
response machine-readable** — you do not have to guess which input produced which
outcome.

**Array batching** sends a JSON array of separate documents:

```bash
curl -s -X POST "$U" -H 'Content-Type: application/json' \
  -d '[{"query":"{__typename}"},{"query":"{__typename}"}]'
```

Far fewer implementations accept it. Probe with the two-element `__typename` array
above: an array of two responses means it is supported. Alias batching is the one
to rely on; array batching is a bonus and a fingerprint.

## What it actually buys you

Not speed — **invisibility to per-request controls**. Ten login attempts inside one
request are, to a counter that increments per request, one attempt. The same holds
for a WAF rule that flags "more than N `/graphql` POSTs per minute per IP", for a
lockout counter keyed on request count, and for an audit log that records one line
per request.

It also defeats **per-object** checks that are implemented per resolver call but
rate-limited per request, and it multiplies every oracle in
`schema-recovery.md` — aliased typo probes harvest many field suggestions at once.

## The finding is the broken counting model — and how to prove it

"No rate limiting" is auto-discarded by this rig
(`../../validation/references/auto-discard.md` row 16), and correctly so. **This is
a different claim**: the target *has* a control, the control *works*, and a
protocol feature walks around it. Prove exactly that, with a differential:

```
1. Sequential positive control — send N identical failing operations as N separate
   HTTP requests, N chosen just past the documented/observed threshold.
   Expect: 429 / lockout / captcha / a changed error. RECORD IT.
   This is the half that proves a control exists at all.

2. Batched — send the same N operations as N aliases in ONE HTTP request.
   Expect: N independent results, no 429, counter unmoved.

3. Re-run step 1 after step 2. The threshold must still trip.
   This rules out "the limit had already reset" and "the account was already locked".
```

Three steps, and the finding is the delta between 1 and 2. Without step 1 you have
"there is no rate limit", which is a discard. **Report the mechanism, not a
cracked credential.**

Keep N small — just past the threshold, typically 5–10 — and run it against **your
own** accounts.

## Where the rig's rules bind

- **Do not run a real credential brute force on production.** It is rung 5, it is
  not needed, and the bounded differential above already demonstrates the defect.
  If the operation is a login, use your own two accounts and a password list of
  your own passwords plus obvious wrong ones.
- **OTP/2FA is the same rule.** Demonstrating that 10 OTP guesses ride in one
  request is the finding; exhausting a 6-digit space is not, and against a real
  user's factor it is out of bounds entirely. `../../auth-flow-bypass/references/mfa-session.md`
  §D owns the framing — state brute-forceability by inference from the demonstrated
  batch size and the absent counter.
- **Enumeration is still enumeration.** A batched account-existence sweep is faster
  discard bait, not a finding, unless the oracle leaks something beyond existence
  (`../../validation/references/auto-discard.md` §"Two discards stacked").
- **Aliased mutations are still writes** — own objects, sentinel values, reverted,
  appended to `writes.jsonl`. An aliased batch makes it trivially easy to write a
  hundred objects by accident; count your aliases before you send.

## Uses that are not brute force

These are where batching converts, because the outcome is data rather than a
guessed secret:

- **Object-id sweeps.** One request, many aliases, many ids — the fastest way to
  establish whether an object endpoint is scoped, and to *count* reachable records
  for the severity ladder. Grade with `../../idor-bola`; if the ids are
  tenant-scoped, `../../tenant-isolation`.
- **Field-suggestion harvesting** — many aliased typo probes per request
  (`schema-recovery.md`).
- **Path comparison** — the same object requested through every path that reaches
  it, in one request, so the responses are directly comparable and no timing or
  session drift explains a difference (`authz-paths.md`).
- **Argument fuzzing** — the same field with an argument varied across aliases:
  `limit: -1`, `limit: 0`, `limit: 99999`, a negative offset, a null. A `-1` that
  is interpreted as "no limit" and returns the whole collection is a real finding
  and needs exactly one alias to spot.

`CrackQL` templates a query with Jinja placeholders and expands a CSV into aliases,
with `-b` to cap batch size under cost controls. Useful; the same thing is a
five-line loop building the document yourself, which is what to do when the tool is
not installed.

## Controls that stop it

Recognize these before concluding an operation is reachable at scale:

- **query cost analysis** — each field carries a cost, the document is scored and
  rejected over a budget. Tell: an error naming a cost, complexity or score.
- **query depth limit** — rejects deeply nested documents. Tell: an error naming
  depth or nesting.
- **amount/node limits** — caps on list sizes and aliases per document.
- **automatic persisted queries (APQ)** — the client sends a `sha256Hash` instead of
  a document. When the server accepts *only* known hashes, arbitrary documents are
  not executable at all and most of this file does not apply. Tell:
  `extensions.persistedQuery` in requests, or a `PersistedQueryNotFound` error.
  **Check whether the server still accepts a full document alongside the hash** —
  an APQ deployment that also honours raw queries has the control in name only.

## The DoS families — recognize, never fire

These all exploit the same client-controlled-complexity property, and every one of
them is a service-degradation action: **rung 5, not attempted**. They are here so
you recognize the exposure, name it in `notes/`, and state reachability by
inference rather than by causing an outage.

| Family | Shape | What makes it possible |
|---|---|---|
| **Circular query** | `paste { owner { pastes { owner { … } } } }` | bidirectional relationships in the schema — small query, enormous response. The most efficient, and visible as a cycle in a Voyager render |
| **Circular fragment** | two fragments spreading each other | the spec forbids it; implementations vary in whether they detect it before or after expanding |
| **Field duplication** | one field repeated thousands of times | large document, processing cost |
| **Alias overloading** | thousands of aliases on one expensive field | same, and it bypasses per-request accounting |
| **Directive overloading** | `@skip(if:false)` repeated thousands of times on one field | directives are unregulated by the spec |
| **Array batch flood** | hundreds of documents in one array | multiplies any of the above |
| **Object-limit override** | `limit`/`max`/`total`/`first` set very high, or `-1` | pagination arguments trusted as bounds |

**The safe half is the schema read.** A cycle in the type graph plus an absent
depth limit and absent cost analysis is a documented, evidenced exposure that
required no traffic. Write that; do not send the payload. The one member of this
family worth *testing* is the last row — a single request with `limit: -1` or a
large `limit` is an ordinary read, and if it returns the whole collection that is a
data-exposure finding, not a DoS.

## Source

Distilled from *Black Hat GraphQL* (Aleks & Farhi, No Starch Press, 2023),
chapters 5 and 7. The safe-ladder posture above is this rig's, not the book's — the
book demonstrates the DoS payloads against a local lab, and firing them at a live
target is out of bounds here regardless.
