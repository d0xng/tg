# The control matrix

A `200` is an observation. A `200` *plus a control that returned something different* is evidence. This file is the set of second requests that turn one into the other.

**Rule:** every verdict — positive or negative — ships with at least one control from this table, and the report quotes both requests. A finding with no control is what a triager closes as "working as intended, that endpoint is public."

---

## The table

| # | control | the request | what it discriminates | when it is mandatory |
|---|---|---|---|---|
| 1 | **No credential** | strip `Authorization`, cookies, and every api-key header | is the endpoint gated *at all* | always, first |
| 2 | **Invented credential** | keep the header, replace the value with something that cannot be real | is the credential **validated**, or merely **present** | whenever any credential is sent |
| 3 | **Malformed vs well-formed-but-fake** | one value of the wrong shape, one of the right shape but unregistered | does the server check **format** or **content** | when #2 returns 200 |
| 4 | **Fabricated object id** | a syntactically valid id that cannot exist | is the `200` a real read, or your own input echoed | every object-reference test |
| 5 | **Owner call** | the same request as the object's legitimate owner | did you *bypass* a check, or does none exist for anyone | before claiming a bypass |
| 6 | **Reverse direction** | B reads A's object after A read B's | rules out session confusion and one-off object state | every cross-account claim |
| 7 | **Enforcing sibling** | the neighbouring endpoint that *does* refuse you | the correct control exists in this codebase and was not applied here | whenever one exists — the strongest line in any report |
| 8 | **Positive control** | one call this credential *should* succeed at, in the same batch | is a negative result enforcement, or throttling | **every negative verdict** |
| 9 | **Post-attack repeat** | re-run the control after the attack succeeded | rules out ordering, caching and throttling artefacts | when the result could be cached |
| 10 | **Read the identity back** | look for an actor field in the *response* — `userId`, `user`, `actor`, `createdBy`, `owner` | did the server resolve **any** identity, or proceed with none | whenever an unauthenticated write is accepted |
| 11 | **The client's own request contract** | read the frontend's fetcher for *this* call — auth wrapper, `skipCSRF`, a registered `401` handler | does the application itself consider this endpoint authenticated | whenever "that endpoint is public by design" is the likely closure |
| 12 | **The app's own status oracle** | a first-party endpoint that reports the precondition — `…/is-verified`, `/status`, `/eligibility`, `/entitlements` | the server certifying, before you act, that the requirement was not met | any bypass of a verification, approval or completion step |
| 13 | **Enumerate what it DOES validate** | send the same request broken in the ways the server *does* reject | proves the missing check is absent by omission, not absent from your test | whenever you claim a check does not exist |

---

## The requests

### 1 · No credential

```bash
curl -sS -o /dev/null -w 'no-cred → %{http_code} %{size_download}B\n' "$URL"
```

Run it on **every verb the resource accepts**, not only `GET`. Multiple corpus findings were unauthenticated on read *and* create *and* delete; testing only `GET` would have produced a Medium instead of a Critical.

```bash
for M in GET POST PUT PATCH DELETE; do
  printf '%-7s ' "$M"
  curl -sS -o /dev/null -w '%{http_code}\n' -X "$M" "$URL"
done
```

### 2 · Invented credential

```bash
curl -sS -o /dev/null -w 'fake-key   → %{http_code}\n' "$URL" \
  -H "$KEYHDR: completely-fake-not-a-real-client"

curl -sS -o /dev/null -w 'fake-bear  → %{http_code}\n' "$URL" \
  -H 'Authorization: Bearer not-a-token-at-all'
```

> This is the single most valuable control in the class. It separates *"a credential leaked"* from *"there is no authentication"* — a different finding, usually a better one, and it forecloses the "that key is public by design" reply.

A route with an authorizer rejects an invalid token. If it returns `200`, no authorizer exists. That is precisely how a presign endpoint in the corpus was proven open.

### 3 · Shape versus value

When #2 returns `200`, find out whether *anything* is being checked:

```bash
# wrong shape entirely
curl -sS -o /dev/null -w 'malformed  → %{http_code}\n' "$URL" -H "$IDHDR: garbage"

# right shape, cannot be real
curl -sS -o /dev/null -w 'well-formed fake → %{http_code}\n' "$URL" \
  -H "$IDHDR: 00000000-0000-0000-0000-000000000000@$SUFFIX"
```

A corpus target rejected the first and accepted the second: it validated the **format** of an organisation identifier and never the **value**. Thirty-two zeros passed. Stating that distinction is what made the report unarguable.

### 4 · Fabricated object id

```bash
curl -sS -o /dev/null -w 'real id    → %{http_code} %{size_download}B\n' "$BASE/$REAL_ID"  $AUTH
curl -sS -o /dev/null -w 'fake id    → %{http_code} %{size_download}B\n' "$BASE/$FAKE_ID"  $AUTH
```

- `200` / `404` split → the read is real, and the split is itself an existence oracle worth noting.
- `200` / `200` with the same body → you are reading your own input. Not a finding.
- `200` / `200` with different bodies → check whether the second is a default object rather than a leak.

### 5 + 6 · Owner call and reverse direction

```bash
# A reads B
curl -sS "$BASE/$B_OBJECT" -H "Authorization: Bearer $A_TOKEN" -o a-reads-b.json -w 'A→B %{http_code}\n'
# B reads A   ← the half that is usually skipped
curl -sS "$BASE/$A_OBJECT" -H "Authorization: Bearer $B_TOKEN" -o b-reads-a.json -w 'B→A %{http_code}\n'
# owner reads own, as the baseline both are compared against
curl -sS "$BASE/$B_OBJECT" -H "Authorization: Bearer $B_TOKEN" -o b-reads-b.json -w 'B→B %{http_code}\n'

diff <(jq -S . a-reads-b.json) <(jq -S . b-reads-b.json) && echo "cross-tenant response == owner response"
```

The corpus report that landed cleanest on a marketplace ran exactly this and stated: *"For each object, the owner and cross-tenant responses matched on every protected field. The server response headers identified the two callers as different authenticated principals, excluding session confusion."*

That last clause matters — show the two callers really were different principals.

### 7 · Enforcing sibling

No fixed command; it is a search. Sweep for the neighbour that refuses you:

- every verb on the same resource
- every operation in the same GraphQL schema, especially ones with the same object type
- every adjacent path segment under the same prefix
- the other API version of the same resource
- the sibling service on the same platform or plane

```bash
for OP in manifest primary component rendition; do
  printf '%-12s ' "$OP"
  curl -sS -o /dev/null -w '%{http_code}\n' "$BASE/$RESOURCE/$OP"
done
```

When the column is not uniform, you have the report. Quote the refusing sibling verbatim in the PoC — it is the strongest single line a report of this class can carry, because it proves the control exists in that codebase and was simply not applied here.

### 8 · Positive control

**Mandatory on every negative verdict.** Two hunters run in parallel against shared accounts, so a burst produces `401` on endpoints that answered `200` a minute earlier — which reads exactly like enforcement.

```bash
# the claim under test
curl -sS -o /dev/null -w 'target   → %{http_code}\n' "$TARGET" -H "Authorization: Bearer $TOKEN"
# something this same token must be able to do
curl -sS -o /dev/null -w 'positive → %{http_code}\n' "$KNOWN_GOOD" -H "Authorization: Bearer $TOKEN"
```

If the positive control also fails, it is throttle, not authorization. Space the requests, re-fire, and **do not write the verdict**.

Check the token's own expiry before trusting any negative:

```bash
cut -d. -f2 <<<"$TOKEN" | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{exp, iat, scope}'
```

### 9 · Post-attack repeat

Re-run the control *after* the attack succeeded. A corpus report notes it explicitly: the control was repeated afterwards with the same result, *"so the outcome is not an artefact of ordering, caching or throttling."*

---

### 10 · Read the identity back

A `201` says the server accepted the write. It does not say *as whom*. Look at what
came back:

```json
{ "id": 84213, "policyId": "...", "userId": null, "createdAt": "..." }
```

`"userId": null` is the server stating, in its own words, that it resolved no
identity and performed the write anyway. That single field is worth more than the
status code, because a `201` is arguable ("perhaps anonymous upload is intended")
and a null actor on a record that belongs to somebody is not.

Look for it in the echoed object, the `Location` resource, and the follow-up read.
Field names that carry it: `userId`, `user`, `actor`, `createdBy`, `owner`,
`submittedBy`, `principal`, `sub`. An `"actor":"anonymous"` or an absent key where
an authenticated call fills one is the same signal.

**Pair it with control 5.** If the same request as the legitimate owner fills that
field with their id, you have both halves: the field exists, it is populated when
an identity is present, and the endpoint ran without one.

**And check what the write reaches.** An unauthenticated write that lands on an
object *belonging to someone else* — a policy, a case, a claim, an order, keyed by
an id from a listing URL — is not "an open upload form". Name whose record it
modified; that is the difference between a Low and the class this control exists
to catch.

**Corpus cases:** `3705759` — `h1/reports/3705759-vodacom_tanzania-duplicate.md`
(critical; the response returned `"userId": null`). The presigned-URL sibling of the
same shape is play 4 in `plays.md`, plus `517efc1f5cbe4d2ba160790bb1752d90` —
`bugcrowd/reports/517efc1f5cbe4d2ba160790bb1752d90-unauthenticated-arbitrary-file-upload-to-production-aws.md`.

### 11 · The client's own request contract

The likeliest closure for a missing-auth finding is "that endpoint is public." The
frontend answers it, statically, before you send anything. Find the call in the bundle
and read **how** it is issued, not just where it points:

```js
// the vulnerable call — issued through the AUTHENTICATED path
createBuyerOffer: (o) => this._authFetcher.post(url, o, { skipCSRF: false })
                          .catch(onUnauthorized /* registered 401 handler */)

// a genuinely public call in the SAME codebase, for contrast
submitLead:      (o) => this._publicFetcher.post('/v1/leads', o)
```

Three tells, and you want all three in the report:

- **which fetcher/wrapper** — apps almost always have two, one that attaches the token
  and one that does not. This call using the authenticated one is the application
  declaring the endpoint's intended posture.
- **`skipCSRF: false`** (or any CSRF opt-in) — nobody CSRF-protects an endpoint they
  believe is anonymous.
- **a registered `401` handler** — the client is written to expect an unauthenticated
  rejection that the server never sends.

Then quote the contrasting public call. "The client treats this as authenticated and
treats `/v1/leads` as public; the server treats both as public" is an argument about
the *developers' own intent*, and it is very hard to answer with "by design".

Cheap, static, and it costs one grep of the bundle you already collected —
`../../js-source-to-sink/references/request-contract.md`.

### 12 · The app's own status oracle

Some flows expose an endpoint whose entire job is to report whether a precondition
holds — `GET /users/{id}/phone/is-verified?phone=…` → `false`, an `/eligibility`
check, an approval `/status`. When one exists, it is the strongest possible framing of
a step-bypass, because the certification comes from the target:

1. call the oracle → it returns **not satisfied**;
2. perform the gated action anyway → it succeeds;
3. call the oracle again → **still** not satisfied.

Step 3 matters. Without it the reader can suppose the action itself satisfied the
precondition as a side effect. With it, the server is asserting the requirement was
never met, before and after the action it was supposed to gate.

This converts a "the SMS screen can be skipped" narrative — which reads as a UI
complaint — into a server-side state-machine defect, with the server as the witness.

### 13 · Enumerate what it DOES validate

To claim a check is missing you must rule out that your test simply failed to trigger
it. Show the checks that *do* fire on the same field:

```
phone = ""                       -> 400 {"message":"Invalid phone"}
phone = <registered elsewhere>   -> 400 {"code":"DUPLICATE_PHONE", ...}
phone = <valid, unverified>      -> 200 published
```

Now the sentence writes itself: *the server validates this field for emptiness and for
uniqueness, and does not validate it for verification.* That is a much stronger claim
than "no validation happened", it is verifiable from three requests, and it survives a
retest by someone who does not trust your setup.

Same shape for authorization: if `403` comes back for one manipulation and `200` for
yours, the authorization layer is live and your case slipped past it.

**Corpus cases:** `3852088` — `h1/reports/3852088-adevinta-duplicate.md` (medium ·
duplicate; controls 12 and 13, plus the bundle showing the verified flag only drives
navigation). `3856521` — `h1/reports/3856521-adevinta-pending-program-review.md`
(high; control 11 in full, with control 7 alongside it).

## Recording it

Every lead body carries this block, filled:

```markdown
**The request that produced this verdict:**   <method, url, headers, body>
**Why that request tests this claim:**        <one sentence>
**Discriminating control:**                   <which control, and what it returned>
**Positive control:**                         <the call that should succeed, and whether it did>
```

And the report reproduces both requests verbatim. Paraphrasing a control is the same as not running it.
