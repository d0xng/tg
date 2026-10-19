# Second-order / stored IDOR -- accepted now, dereferenced later

> **This file is the single owner of second-order / stored object references for the pack.**
> `vectors.md` §11 keeps the one-line recognition card and routes here.

The distinguishing property: **the id you control is accepted now and dereferenced
later, in a different context** -- usually a more privileged one, often asynchronous,
often rendered for somebody else. The write returns a boring `200 {"ok":true}` and
nothing in that response is the finding. That is exactly why it gets missed: the
first-order tester swaps the id, sees a 200 with no foreign data in the body, files
"accepted but nothing returned", and rotates away one call before the proof.

## Contents

- Why it is missed
- The universal procedure
- §1 -- Stored reference on your own record, rendered by another surface **(the core shape)**
- §2 -- Stored destination: webhook / callback / delivery target (URL half -> `ssrf-safe`)
- §3 -- Batch / bulk / async jobs: validated at submit, not at run
- §4 -- Invitations, share links, delegation (identity-proof half -> `broken-access-control`)
- §5 -- Import / copy / duplicate / template carrying a source id
- §6 -- Queue / scheduled task running under a service identity
- Forcing the later dereference (trigger table)
- Negative controls (both mandatory) + the enforcing sibling
- Rungs / Converts? / Evidence

## Why it is missed

Three response bodies that all look like "not a finding" and all mean "keep going":

| What you see on the write | What it actually means |
|---|---|
| `200 {"ok":true}` / `204` | the reference was **stored**; nothing was resolved yet |
| read-back echoes the id only (`{"avatar_asset_id":"<B's id>"}`) | the write API returns the *pointer*, never the *pointee* -- the pointee appears in the render |
| `404` when you plant a **nonexistent** id | the lookup is **real** and runs at write time -- so a foreign id that is *accepted* was resolved and passed ownership-free |

The last row is the tell that converts the whole class: the server clearly resolves
the id (it can tell a nonexistent one from a real one) and clearly does not check who
owns it.

## The universal procedure

1. **Find every write that stores a reference rather than a value.** Field-name shapes:
   `*_id`, `*_uuid`, `*_key`, `*_ref`, `*Id`, `attachment_id`, `document_id`,
   `avatar_asset_id`, `logo_id`, `signature_id`, `template_id`, `source_id`,
   `channel_id`, `destination_id`, `payment_method_id`, `address_id`, `report_id`.
   A reference is anything the server will have to *look up again later*.
2. **Plant B's id from A's session** (both accounts yours). Record the original value
   first so you can revert.
3. **Locate the later surface** that resolves it -- the export, the PDF, the invoice,
   the email, the share/unfurl preview, the worker, the scheduled run.
4. **Force that dereference** (trigger table under "Forcing the later dereference"
   below) and read the render, not the write.
5. **Run both negative controls** before calling it.

Working shapes, all against a host you were handed. `$H` is the in-scope host, `$A_AUTH`
is account A's `Authorization:`/`Cookie:` header, `$B_OBJ` is an object id owned by your
second account B.

```bash
# 0. baseline / enforcing sibling -- the CANONICAL route does check ownership
curl -s -o /dev/null -w 'canonical A->B: %{http_code}\n' "$H/api/v1/assets/$B_OBJ" -H "$A_AUTH"
#    -> 403   (this 403 is what makes the render below a bypass rather than a shared object)

# 1. plant the foreign reference on A's own record -- the boring 200
curl -s -X PATCH "$H/api/v1/me/profile" -H "$A_AUTH" -H 'Content-Type: application/json' \
  -d "{\"avatar_asset_id\":\"$B_OBJ\"}" -w ' <- HTTP %{http_code}\n'
#    -> {"ok": true} <- HTTP 200        nothing here is the finding

# 2. the write-side read-back only echoes the pointer -- this is where hunters stop
curl -s "$H/api/v1/me/profile" -H "$A_AUTH" | jq -c .
#    -> {"avatar_asset_id":"<B's id>"}
```

## §1 -- Stored reference on your own record, rendered by another surface

**Recognize:** any id stored on your profile/settings/org record that some *other*
surface resolves later -- avatar, logo, e-signature, header image, default attachment,
default template, a document/attachment id on an invoice line, a report reference.
The rendering surface is the export, the PDF/print view, the emailed copy, the
invoice, the certificate, or the public share/unfurl preview.

**Plant:** the `# 1.` call in the block above (record the original value first).

**Force the dereference and read the render:**

```bash
JOB=$(curl -s -X POST "$H/api/v1/exports" -H "$A_AUTH" -H 'Content-Type: application/json' \
        -d '{"format":"pdf"}' | jq -r '.job_id')
for i in $(seq 1 20); do                       # bounded poll -- never an unbounded until-loop
  R=$(curl -s "$H/api/v1/exports/$JOB" -H "$A_AUTH")
  [ "$(printf '%s' "$R" | jq -r '.status')" = queued ] || break
  sleep 1
done
printf '%s' "$R" | jq -c '{status, dereferenced: .render.avatar}'
```

**Oracle -- the render carries B's field values, not A's and not a placeholder:**

```
{"status":"done","dereferenced":{"id":"<B's id>","filename":"acme-q3-payroll.pdf",
 "owner_email":"b@operator.test","tenant":"org_b"}}
```

`tenant`/`owner_email`/`filename` are B's while the canonical route returned **403** for
the identical account. That pair -- 403 on the direct read, B's fields inside A's export
-- is the finding. A render that falls back to a default/placeholder image, or errors
`asset_not_found`, is authz working at the dereference: not a finding, note it and rotate.

**Differential helper.** Render twice, once with an id you own and once with B's, and
diff the two artifacts:

```bash
render() {                       # $1 = object id to plant; prints the LATER render
  curl -s -o /dev/null -X PATCH "$H/api/v1/me/profile" -H "$A_AUTH" \
       -H 'Content-Type: application/json' -d "{\"avatar_asset_id\":\"$1\"}"
  J=$(curl -s -X POST "$H/api/v1/exports" -H "$A_AUTH" -H 'Content-Type: application/json' \
       -d '{"format":"pdf"}' | jq -r .job_id)
  for _ in $(seq 1 20); do
    R=$(curl -s "$H/api/v1/exports/$J" -H "$A_AUTH")
    [ "$(printf '%s' "$R" | jq -r .status)" = queued ] || break
    sleep 1
  done
  printf '%s' "$R" | jq -S '.render.avatar'
}
render "$A_OBJ" > own.json ; render "$B_OBJ" > foreign.json ; diff own.json foreign.json
```

**Run the two renders SEQUENTIALLY, never in `diff <(render …) <(render …)`.** Process
substitution starts both subshells at once; they overwrite the *same* stored field
before either job runs, both artifacts come back identical, and `diff` exits 0 -- a
false negative that reads exactly like "authz enforced". (Verified: the process-
substitution form returned no diff on a target where the sequential form returned the
full field-by-field difference.)

For a binary artifact (a real PDF/PNG rather than a JSON render), the same oracle with
the bytes: `curl -s "$H/api/v1/exports/$JOB/file" -H "$A_AUTH" -o out.pdf`, then
`strings out.pdf | rg -i '<B-distinguishing-string>'`, or compare `sha256sum` of the
own-id artifact and the foreign-id artifact -- differing hashes plus B's string in the
foreign one is the same proof.

## §2 -- Stored destination: webhook / callback / delivery target

Two different bugs share this shape; separate them before you write the lead.

**(a) The stored value is a URL the server fetches later.** That is stored/second-order
SSRF -- the object half ends here, the fetch half is owned by
`../../ssrf-safe/references/case-patterns.md` ("Webhook register-then-test port
oracle"): register the destination with no validation, then pull the "send test event"
action that fires it server-side. Recognize it here, then run `ssrf-safe`.

**(b) The stored value is a destination *id* belonging to another tenant** -- a channel
id, an integration id, a mailbox id, a delivery-profile id. This one is yours:

```bash
# store a foreign destination id on your own record -- no ownership check
curl -s -X POST "$H/api/v1/webhooks" -H "$A_AUTH" -H 'Content-Type: application/json' \
  -d '{"channel_id":"<B-channel-id>"}' -w ' <- HTTP %{http_code}\n'
#   -> {"ok": true} <- HTTP 200

# the later "test"/first real event dereferences it
curl -s -X POST "$H/api/v1/webhooks/self/test" -H "$A_AUTH" -H 'Content-Length: 0' \
  | jq -c '.delivered_to | {id, url, tenant, secret_present:(.secret!=null)}'
#   -> {"id":"<B-channel-id>","url":"https://acme-internal.example/hook",
#       "tenant":"org_b","secret_present":true}
```

**Oracle:** the dereference response (or the delivery log/receipt) exposes the foreign
channel's `url`, `tenant`, or -- the severity jump -- its signing `secret`. Both
directions are impact: A's events now flow into B's internal endpoint (data leak *to* a
third party), and A learns B's internal URL + signing secret (which forges B's events).
If the render returns only `{"delivered":true}` with no foreign field, you have an
accepted reference and no proof -- keep hunting for a surface that echoes the resolved
destination (a delivery log, a retry queue, an integrations list).

**Never point a stored destination at a real customer's endpoint** and never fire a
delivery that reaches a mailbox or webhook you do not own -- that is rung 5 — not attempted: ask d0x directly before executing.

## §3 -- Batch / bulk / async jobs: validated at submit, not at run

**Recognize:** any endpoint taking an **array** of ids -- `/batch`, `/bulk`, `/reindex`,
`/export`, `/merge`, `/archive`, `/send`, `/recalculate` -- or a job submitted now and
executed by a worker later. Two independent gaps live here: the per-item check at
submit is presence-only (not ownership), and the worker never re-checks against the
submitter at run time.

```bash
# the submit-time check EXISTS -- an unknown id is rejected. This is the proof the id
# is genuinely resolved at submit, so an ACCEPTED foreign id was resolved ownership-free.
curl -s -X POST "$H/api/v1/batch/reindex" -H "$A_AUTH" -H 'Content-Type: application/json' \
  -d '{"ids":["<A-obj>","<nonexistent-id>"]}' -w ' <- HTTP %{http_code}\n'
#   -> {"error": "unknown_ids", "unknown": ["<nonexistent-id>"]} <- HTTP 400

# now A's own id + B's id: accepted, and the WORKER resolves both with no owner check
JOB=$(curl -s -X POST "$H/api/v1/batch/reindex" -H "$A_AUTH" -H 'Content-Type: application/json' \
  -d '{"ids":["<A-obj>","<B-obj>"]}' | jq -r .job_id)
for i in $(seq 1 20); do
  R=$(curl -s "$H/api/v1/batch/$JOB" -H "$A_AUTH")
  [ "$(printf '%s' "$R" | jq -r .status)" = queued ] || break
  sleep 1
done
printf '%s' "$R" | jq -c '[.results[] | {id, tenant, owner_email}]'
#   -> [{"id":"<A-obj>","tenant":"org_a",...},{"id":"<B-obj>","tenant":"org_b","owner_email":"b@…"}]
```

**Oracle:** the job result set contains B's record with B's field values, fetched by the
worker, returned to A's session. Sub-oracles worth capturing separately: the mixed batch
where the first item is yours and later items are not (some implementations authorize
only `ids[0]`); and the **partial-failure body**, which frequently leaks existence/field
data about ids the caller has no access to (`{"failed":[{"id":"<B-obj>","reason":"locked
by b@operator.test"}]}`) -- that alone is an enumeration oracle even when the batch is
otherwise enforced.

Keep batches **bounded to a handful of ids** (safe-ladder rung 3). A bulk job is the one
place where "prove scale" turns into a real load event on the target's worker fleet --
prove the class on 2-3 items and state the rest by inference.

## §4 -- Invitations, share links, delegation

**Recognize:** an invite / share / delegation object created now and *redeemed later*,
carrying an id the acceptance step trusts: `org_id`, `team_id`, `resource_id`, `role`,
`inviter_id`, `seat_id`, `scope`. The check happens at creation (can you invite?) and
the acceptance handler simply applies whatever the stored record says.

- **Plant at creation:** `POST /api/v1/invites {"email":"<A@yours>","org_id":"<B-org>",
  "role":"admin","resource_id":"<B-obj>"}` from A's session -- an org/resource A does not
  belong to. The creation 200 is not the finding.
- **Force the dereference:** redeem it from the session of the account you addressed it
  to -- yours (`POST /api/v1/invites/<token>/accept`) -- then read the canonical
  membership/permission route. Never send an invite to an address you do not own.
- **Oracle:** after acceptance, `GET /api/v1/me/memberships` (or the org's member list)
  shows the account inside B's org / holding the elevated role, **and** a previously-403
  route on B's object now returns 200. Membership state read back from the canonical
  route is the proof; the acceptance 200 is not.
- **Variant -- share link with an embedded object id:** create a share for an object you
  own, then edit the stored `resource_id` (or re-create the share with B's id) and open
  the link **anonymously in a clean session**. Anonymous retrieval of B's object through
  your share token is a materially worse finding than an authenticated one, because the
  artifact is now reachable without any account.

> The *identity-proof* half of this surface -- unverified email accepting an invite,
> tokens not bound to the recipient, SSO/SCIM linking on email equality, recovery to a
> secondary address -- is owned by
> `../../broken-access-control/references/invitation-identity.md` §B. What stays here is
> the **stored object/tenant/role id trusted at redemption**. Run both if the flow has both.

## §5 -- Import / copy / duplicate / template carrying a source id

**Recognize:** `POST /<object>/<SRC>/copy`, `/duplicate`, `/clone`, `/import`,
`{"template_id":…}`, `{"source_id":…}`, "start from an existing X", "restore from
backup", "apply this preset". The source id crosses the tenant line and is dereferenced
by the copy job -- often minutes later, often by a worker.

- **Attack:** submit the copy/import with **B's** object as the source and your own
  identity as the destination, then read the resulting object through your normal
  authenticated route.
- **Oracle:** the new object in A's account carries B's content/fields (name, body,
  attachment references, embedded credentials, S3 keys under B's prefix). If the copy
  keeps a *reference* rather than copying bytes, the proof is one step further out --
  open/export the copy and confirm the render pulls B's asset (§1 oracle).
- **Round-trip variant:** export an object you own, tamper the embedded `owner`/`tenant`/
  `visibility`/`source_id` fields in the archive, re-import, and read the result.
- **Negative control:** the same copy with a nonexistent source id -> `404`/`unknown
  source`, proving the source is genuinely resolved.

> The *function-level* half -- "direct create is 403 for this role but `copy` is not" --
> is owned by `../../broken-access-control/references/workflow-state.md` (clone/copy/
> import bypass), and the caller-controlled-destination + foreign-source hybrid on an
> internal gateway is `../../broken-access-control/references/role-matrix.md` §2. What
> stays here is the **carried source id and its deferred dereference**.

## §6 -- Queue / scheduled task running under a service identity

The reason this whole class outscores plain IDOR: the deferred dereference frequently
does **not** run as you. It runs as the worker, the renderer, the mailer, the cron -- a
service identity with broader rights than any tenant, precisely because it must serve
every tenant.

**Recognize:** a "run now" control, a schedule/cron builder, a retry button, a report
subscription, a recurring export, an alert rule, an emailed digest. Anything storing
`{"schedule":…, "target_id":…}` or `{"recipients":[…], "report_id":…}`.

- **Plant:** store the task with B's `target_id`/`report_id` from A's session.
- **Force:** the "run now"/"send test"/"preview" control if one exists; otherwise let one
  tick pass. Prefer the manual trigger -- it is bounded; a schedule you forget keeps
  firing (see the revert rule below).
- **Oracle -- the privilege delta:** the task result contains fields that *no tenant
  session returns*. Compare three reads of the same object id: A's session -> 403;
  B's own session -> B's tenant-visible fields; the task output -> B's fields **plus**
  internal ones (`internal_notes`, `cost_basis`, `pii_verified`, raw ids, a presigned
  URL). That third column is the service identity leaking through, and it is what turns
  a High into a Critical.
- If the task output is delivered rather than displayed, keep the recipient **your own
  address only**. A scheduled send whose recipient list contains anyone else is rung 5.

## Forcing the later dereference

The reference is planted; the finding is whichever of these you can pull.

| Stored where | Trigger you can pull yourself |
|---|---|
| profile / org avatar, logo, signature, header | request an account export, generate the PDF/print view (`?format=pdf`, `/print`, `/download`), "email me a copy" to your OWN address |
| attachment / document id on a record | the record's export, invoice, receipt, certificate, or its share/preview URL |
| template / theme / preset id | render any document that uses the template |
| webhook / channel / destination id | "send test event", or a natural event on a record you own |
| batch / import item ids | the job runner: "run now", "retry", "reprocess" |
| scheduled task / subscription | "run now" / "preview"; otherwise one tick |
| anything on a public-facing profile | the **anonymous** share/unfurl/preview fetch -- open it in a clean session with no cookies |
| nothing obvious | search the JS for the render surface (`js-source-to-sink`): the export/preview route is frequently absent from the UI but present in the bundle |

If no trigger is reachable, the finding is **not proven** -- it is a lead. Write it to
`leads/` with `status: unproven` and the exact next call, per
`../../_shared/references/output-contract.md`. Do not upgrade "the reference was
accepted" into a finding.

## Negative controls (both are mandatory) + the enforcing sibling

`validation` rejects a second-order claim without these, because "the export shows an
image" is otherwise indistinguishable from a shared/public asset.

1. **Same flow, an id you own** -> the render must show **your** object. This proves the
   render actually dereferences the stored field rather than emitting a fixed default.
   Observed shape: `{"id":"<A-obj>","tenant":"org_a"}`.
2. **Same flow, a nonexistent id** -> `404` / `asset_not_found` (at the write, or at the
   render). This proves the lookup is real, so an accepted foreign id was *resolved*,
   not ignored. Observed shape: `{"error":"asset_not_found"} <- HTTP 404`.
3. **The enforcing sibling** -> the canonical direct read of B's object from A's session
   returns `403`. "The direct route denies, the render does not" is the single strongest
   convert argument for this class.

Then **revert**: restore the original stored value (the id you recorded in step 2 of the
procedure), delete the schedule/webhook you created, and cancel any recurring job. A
planted reference left behind is a live cross-tenant leak you created.

## Rungs

Safe ladder: `../../_shared/references/safe-ladder.md`.

- **Rung 2 throughout.** Both ids are yours: A plants, and the "victim" object belongs to
  your own second account B. The write mutates **your** record, never B's -- that is why
  this class is safely provable end-to-end at rung 2. Revert immediately after the render.
- **Rung 1** for the baseline and the enforcing sibling (plain reads).
- **Rung 3** caps the batch: 2-3 ids, not a bulk run; the worker fleet is shared.
- **Rung 4** if the program confines cross-tenant/privacy proofs to UAT/OAT -- plant and
  render there in full, and state the prod-equivalent impact by inference.
- **Rung 5 -- not attempted, ask d0x directly before executing:** a stored id pointing at a **real** user's or a
  real tenant's object on prod, any dereference that **delivers** to a mailbox/webhook/
  channel you do not own, and any recurring schedule you cannot immediately cancel. The
  danger is specific to this class: the deferred dereference can push a real customer's
  data into a durable artifact (a PDF, an emailed invoice, a public preview) that you
  cannot recall. Prove it on B, state prod by inference.

## Converts?

**Honest verdict.** This class usually scores **above** the equivalent first-order
id-swap, for two reasons a triager accepts: the dereference happens in a **privileged /
service** context that returns fields no tenant session returns, and the output lands in
a **durable artifact** (PDF, invoice, email, public preview) rather than a transient API
response.

- **High** -- the later render returns another tenant's business data or PII, and the
  canonical direct read of the same object returns 403.
- **High** -- the stored destination dereference exposes a foreign tenant's internal URL
  plus its webhook signing secret (forging their events is the stated impact).
- **Critical** -- the artifact is retrievable **anonymously** (share/unfurl/preview), or
  the service-identity render leaks auth material (presigned URL, token, signing secret),
  or the acceptance/delegation path lands you inside the victim org with a role.
- **Medium** -- the render resolves the foreign reference but returns only non-sensitive
  metadata (a filename, a thumbnail, a display name), or the invite lands you in the org
  with no readable data behind it.

**What gets it closed as informative:**

- The write `200` is the whole report. "The API accepted another user's asset id" with no
  render is discovery, not impact -- the most common way this class is thrown away.
- The render falls back to a placeholder/default, or errors `not_found` -- authz is
  enforced at the dereference; the write endpoint is just sloppy about validation.
- The referenced object was public anyway (a CDN-public asset, a shared template, a
  published record). Prove the 403 baseline **before** the render or expect a "works as
  intended".
- The "other tenant" is one your account legitimately reaches through an org/parent
  relationship -- that is own-tenant access, not a boundary crossing.
- Only the artifact's existence is shown, without the field-by-field diff proving the
  content is B's.

## Evidence

Beyond the standard checklist in `../SKILL.md`, a second-order lead must carry:

1. the **plant** request (A's session, B's id) **and** its unremarkable `200` -- state
   plainly that this response is not the finding;
2. the **trigger** you pulled to force the dereference, verbatim;
3. the **render** with B's distinguishing fields, redacted but distinct enough to prove
   ownership (`tenant`, `owner_email` domain, filename);
4. **negative control 1** (own id -> own object in the render);
5. **negative control 2** (nonexistent id -> 404, so the lookup is real);
6. the **enforcing sibling** (`403` on the canonical direct read of B's object from A);
7. the **context of the dereference** -- who runs it (your session, a worker, a service
   identity, an anonymous preview fetch) and where the output lands (screen, PDF, email,
   public URL). This is the sentence that sets the severity;
8. confirmation that the planted reference was **reverted**.

Write it to `targets/<program>/leads/` in the format in
`../../_shared/references/output-contract.md`; `surface` is `idor`, and keep the claim
string stable (`second-order <field> -> <render surface>`) so dedup works next session.
