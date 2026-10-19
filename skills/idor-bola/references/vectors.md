# IDOR/BOLA vectors -- full catalog (read on demand)

The `../SKILL.md` names the canonical vectors and the rotate/abandon rule. This is
the deep expansion: how each vector works, its oracle, and the bypass to try when
the naive swap is blocked. Each technique lives here ONCE -- the skill body
references it. Rotate angles (3 tries -> next); abandon the boundary only when all
are spent (see ../SKILL.md).

## Where identity lives (the general class -- cover ALL of it)

- **Path ids** -- /users/{id}; nested /orgs/{o}/projects/{p}/files/{f} (test EACH segment independently -- the outer may be checked, the inner not).
- **Query ids** -- ?account=, ?userId=, ?tenant_id=, ?id=.
- **Body ids** -- user_id, account_id, owner, created_by, recipient_id, tenant_id, org_id, to, invoice_id. Shapes: POST /messages {"to":"<B>"}, POST /export {"user_id":"<B>"}.
- **Header / cookie identity** -- tenant/org/account headers used as routing keys; a cookie-borne id.
- **List vs detail** -- a list endpoint almost always has a matching detail endpoint; infer and test it (GET /orders -> GET /orders/{id}).
- **Nested / related** -- /orders/{mine}/refunds/{not-mine}.
- **Response-based leak** -- where authz IS enforced but the error body differs owner vs non-owner: NOT IDOR, but a **username/existence enumeration oracle** -- capture it as a separate low lead, don't fold it into the IDOR finding.

## Bypass ladder (rotate when A+B-id returns 403/404/own-data)

1. **API-version downgrade.** Old versions often lack the authz middleware added later. Replay against /api/v1/, /api/, /api/legacy/, drop the version prefix, or swap v2->v1 in nested paths. A version that drops the check is a full IDOR.
2. **HTTP-method swap.** GET blocked -> try POST/PUT/PATCH (a write path may skip the read guard); HEAD/OPTIONS differentials leak existence.
3. **Wrapper / nested param.** Move the id into a nested object {"filter":{"user_id":"<B>"}}, an array {"ids":["<B>"]}, or a wrapped envelope -- middleware often only checks the top level.
4. **Mass-assignment of ownership.** On create/update, add owner_id/user_id/tenant_id/account_id/org_id to plant or steal an object across the boundary (POST /items {"name":"x","owner_id":"<B>"} -> read it back).
5. **Tenant/org header routing.** The boundary is a header (x-tenant, x-account-id, accountId, x-org-id, x-*-org-id). The list endpoint is scoped/empty for non-members, but the per-object route takes the org from the header and uses it as a **routing key** with no membership check -> set the victim's org header + the victim's object id. **Tell:** wrong org -> 404 routing miss vs valid-foreign org -> 200.
   **Owner:** `../../tenant-isolation/references/tenant-vectors.md` §1 owns the read method and §2 the entitlement/cost-amplification twin (including the enforcing-sibling convincer and the all-zeros-uuid probe). Recognize the header here, then run `tenant-isolation`.
   Converts: **High** when the foreign-tenant response carries tenant-scoped business data or PII; **Medium** when it is non-sensitive metadata only; **Critical** when it reaches mass PII (an org user list, or 5–10 distinct bounded records).
6. **Body-field identity spoof.** Auth is a signed Bearer (+ maybe a public api-key), but the handler trusts an identity field in the JSON body (a field like user_id / userId / ownerId / author) and never compares it to the token sub.
   **Owner:** `../../broken-access-control/references/graphql-api.md` §1 owns the oracle ladder. Converts: **Medium** (attribution / metric / RLHF poisoning). Raise it only by proving the read side or a downstream routing effect (moderation / Trust-&-Safety queue).
7. **JWT / signed-token confusion.** Is the token verified or merely decoded? Try alg:none + empty signature + swapped user_id/sub; submit a **claim-vs-path mismatch** (claim=A, path=B -- see which wins); look for a response that **embeds another user's token** (IDOR on the token itself -> direct impersonation). Token forgery itself (`alg:none`, RS256->HS256, `kid`/`jku`/`x5u`) is owned by `../../auth-flow-bypass/references/jwt-attacks.md` — the embedded-token IDOR and the claim-vs-path outcome stay here. For an access token carrying a **self-writable authz claim** (a Cognito `custom:*` tenancy attribute), the user overwrites it to the victim tenant, re-auths, and crosses the boundary -- **revert the claim after**; the tenant chain is owned by `../../tenant-isolation/references/cognito-takeover.md` and the AWS `X-Amz-Target` API mechanics by `../../cloud-exploitation/references/cognito.md` §5c.
8. **Dual-authorizer route.** A second/internal `*.execute-api` host where most routes reject your JWT with an IAM/SigV4 error but a few accept any user's `id_token` with zero ownership check. **Owner:** `../../broken-access-control/references/role-matrix.md` §2. Converts: **High** when a JWT-accepting route lacks the ownership check AND a caller-controlled destination exposes another account's object; **Medium** if only the authorizer gap is proven.
9. **Encoding / hashids / opaque ids.** Try the id base64-decoded then re-encoded, URL-encoded (%2F, ..), an integer where a hashid is expected, or decode a hashid/short id to the underlying sequential int.
10. **GraphQL node id.** Swap id / node(id:) to another user's (often base64("User:<n>")); introspect for fields not in the UI. Full aliasing/batching enumeration -> patterns.md.
11. **Second-order.** The id you can't reach directly may be settable elsewhere and read back later (set recipient_id on a draft, read via another endpoint), or leaked into an export/notification you then consume. **Owner:** `second-order.md` -- the full stored-reference class (profile/attachment id resolved by an export or PDF, stored webhook/destination id, batch/async jobs re-checked only at submit, invite/share/delegation ids trusted at acceptance, import/copy source ids, service-identity queue runs), including the force-the-dereference table and the two mandatory negative controls. Recognize it here, open that file to run it.

## Race / TOCTOU on an object you reference (recognition only)

Same missing check as an IDOR, exploited in the **time** dimension rather than the id dimension: the server validates an object reference and then acts on it as a separate, unsynchronized step, so two in-flight requests both pass the same check.

Recognize it -- do not start firing:

- **check-then-act on an object you reference**: the handler reads state (ownership, balance, status, membership) and writes based on that read, with no lock/transaction/version column. The tell is a `status`/`used`/`claimed`/`version` field that the response shows flipping.
- **a single-use token**: an invite, share link, coupon, reset token, gift card, referral or one-time code that should be consumable exactly once at redemption.
- **a limit that should be enforced once**: seat/member count, plan quota, one-vote/one-claim/one-review-per-object, a "you already did this" guard, a withdrawal or transfer that should decrement.
- **the second-order adjacency**: the id is validated at submit and dereferenced at run (`second-order.md` §3) -- if the window between the two is caller-observable, the same surface has both bugs.

> **Owner:** `../../broken-access-control/references/race-conditions.md` owns the method entirely -- the bounded concurrency shape, the oracle, the rungs, and the hard rule that a financial/payment action is never fired — d0x's approval before execution. Do not improvise a race here: recognize the shape, then open that file and run it from there.

## ID-type playbooks

| ID type | Play |
|---|---|
| **Sequential numeric** | Confirm A vs B, then a **bounded, paced** sweep (5-10 ids) to prove scale -- never dump the table; respect rate limits. A/B alone already earns High if the object carries PII; the sweep is what raises non-PII metadata to High and what supports the mass-PII Critical. |
| **UUID / GUID** | Not safe -- it just has to **leak**. Harvest from side channels: email headers, notification payloads, exports, JS vars, Referer, error messages, avatar/asset CDN paths that embed the id, a public roster endpoint. v1 UUIDs (time+MAC) are predictable -- generate adjacent ones. |
| **GraphQL node** | base64("Type:<n>") -- decode, swap, re-encode; introspect hidden fields; alias/batch (patterns.md). |
| **JWT claim** | Decode; test alg:none, claim-vs-path mismatch, embedded-token leaks, self-writable authz claims. |
| **Hashids / short / base64** | Decode to the underlying id, enumerate there, re-encode. |
| **Structured / templated** | A "random-looking" id that is actually a composite template with tiny real entropy. Recognize it: a job/resource id built from a fixed prefix + values that leak from your own activity (a workflow/run id from your own runs) + a date window + a short random suffix; or a storage-key/path built from org/user/resource ids you already hold, so it is fully derivable once you have those parts. **Play:** decompose the id, pin every segment you already know or can leak, and enumerate only the small remainder (the random suffix or the date window), not the whole id space. Decompose before assuming a templated id is unguessable. |

## Bounded enumerator (copy-paste; prove SCALE, never dump the table)

Once A-vs-B is confirmed on a sequential/enumerable id, a **bounded, paced** sweep of 5-10 ids shows the range is open: it raises a non-PII metadata read Medium -> High, and supports the mass-PII Critical. It is **not** a prerequisite for High on a PII object -- one object each way with two operator-owned accounts already anchors that (rung 2). Keep it small -- enough to prove scale, not a flood (rung 3: past the first handful, scale is proven by inference, not by exfiltration).

curl loop + jq field extraction (pin the distinguishing fields so the proof is self-evident, not raw PII):

```bash
S='<A-session-cookie-or-bearer>'
for i in $(seq 1000 1010); do
  curl -s -H "Cookie: session=$S" "https://<in-scope-host>/api/orders/$i" \
    | jq -c '{id, email: .user_email, total, last4: .card_last4}'
  sleep 0.3   # pace it -- never DoS a fragile/single-threaded backend
done
```

ffuf, matched to the hits that actually returned an object (the body oracle, not every 200):

```bash
ffuf -u "https://<in-scope-host>/api/orders/FUZZ" \
  -w <(seq 1000 1100) \
  -H "Cookie: session=<A-session>" \
  -mc 200 -mr '"user_email"' \
  -rate 5 -o idor-orders.json -of json
```

`-mr '"user_email"'` keeps only responses whose BODY carries the PII field, so the output is confirmed cross-account reads, not 200-shells. Stop at the first 5-10 distinct victims. **If you hit a rate limit, STOP** -- degrading availability is out of bounds even in scope. Redact harvested PII in evidence; keep ids in `id=<n>` form so reproduction and dedup survive redaction.

## IDOR -> ATO (the escalation that turns High into Critical)

The highest-converting IDOR escalation: the cross-account read exposes a **credential / reset / 2FA field**, and you complete the takeover on your OWN session. Never against a real user -- run the full chain across your two own accounts (A reads, B is the victim you control), then state the stranger-equivalent impact by inference. Live-session ATO on prod against anything but your own accounts is rung 5 -> **not attempted: ask d0x directly before executing**.

1. **Find the auth-bearing field.** An object that carries a password-**reset token**, an email-verification / magic-link token, a 2FA/TOTP seed (`otpauth://...` / a base32 secret), an OAuth `code`, or a settable `email`/`phone`.
2. **Confirm the cross-user read** via the id-swap (oracle: the token is B's, distinct from A's -- see the confirmation oracle in ../SKILL.md).
3. **Complete the takeover on YOUR session:**
   - **Reset-token read:** trigger "forgot password" for B (your controlled victim) -> read B's reset token via the IDOR -> POST it to the reset-complete endpoint from your own session -> set a new password -> log in as B. That end-to-end login is the Critical proof.
   - **2FA seed read:** feed the leaked base32 seed to a TOTP generator -> you now mint B's valid codes on demand -> the second factor is defeated.

     > **Tooling:** `oathtool` is **not installed on this host**. Install it first — `sudo apt install -y oathtool` — or use the alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.

     ```bash
     oathtool --totp -b '<seed>'                                                  # after the apt install
     pipx install pyotp && python3 -c "import pyotp;print(pyotp.TOTP('<seed>').now())"   # no-apt alternative
     ```

   - **Settable email/phone (write IDOR):** `PUT /api/accounts/{B}/email` with your address -> trigger the reset -> receive it -> ATO. Write side only against your own B; revert immediately after.
4. **Discipline & handoff.** Prove the read (rung 1-2) always; complete the login only across your own two accounts (or on UAT per RoE, rung 4). On prod against a real user, state the ATO by inference from the confirmed token read. Hand the confirmed field to **validation** before claiming Critical.

## Vertical / function-level BAC

A low-priv -- or **guest/anonymous** -- token reaching an admin-only route namespace with no role check. The admin request often exists **only in JS**, never in the UI: capture it with `js-source-to-sink` and replay with a regular/guest session. Proofs: full users list, change another user's role, read internal config. When you find one admin route, map the rest of the admin-namespace route group and read **one row from each**, then take the bounded 5-10-record scale proof in `../../broken-access-control/references/role-matrix.md` §1 and STOP. **Never paginate the table** — state the scale by inference from the `count` or the pagination header (safe-ladder rung 3).

> **Owner:** the full method — minting the guest token, bucketing the admin-namespace route group, the enforcing-sibling oracle, the WAF-origin bypass, and the bounded scale proof — lives in `../../broken-access-control/references/role-matrix.md` §1. Recognize it here, then run `broken-access-control`; keep any residual object-id half in this skill.
Converts: **Critical** when the admin group returns cross-user PII; **High** when it returns non-PII privileged data. The reachable route alone is not a finding.

## Unauth API-Gateway -> datastore proxy

A config key points at `*.execute-api.<region>.amazonaws.com/<stage>` (not the vendor's own domain). **No-auth oracle:** an empty-body POST returns a DynamoDB SDK validation error (Value null at 'tableName' failed to satisfy constraint) instead of 401/403 -> the Lambda passed your input straight to the SDK. Even with no read handler you can READ via ReturnValues:"ALL_NEW" (UpdateItem adding a throwaway attribute) or ALL_OLD (DeleteItem -- only on items YOU created). Recognize it here; the full CRUD method and the `ReturnValues` side-channel are owned by `../../cloud-exploitation/references/dynamodb.md` — run `cloud-exploitation` yourself with the gateway host and stage intact.
