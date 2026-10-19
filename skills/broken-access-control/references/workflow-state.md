# Workflow & State-Transition Checks

Use for actions allowed only in certain states/roles/tiers/workflows: reports,
policies, exams, boards, agents, referrals, leads, orders, tickets, documents,
approvals, payouts, subscriptions. Safe ladder:
the **Rung mapping** above.

## Method

1. Map allowed states/actors from UI, docs, status labels, and API responses.
2. Capture the privileged transition as an allowed actor (exact request).
3. **Negative control**: try the transition as the restricted actor / from the wrong
   state → record the denial.
4. Replay via an alternate route: clone, duplicate, import, copy, mobile API,
   GraphQL, bulk action, retry, or the direct endpoint (skip the UI wizard).
5. Verify persisted state with a canonical read, plus downstream effects.

## Clone / copy / import bypass

`create` is restricted; `clone`/`copy`/`import` recreates the same privileged object
because the permission check lives on the create route but not the copy route.

```bash
# direct create is blocked for the restricted actor
curl -s -X POST "https://$HOST/api/projects" -H "$LOW_AUTH" -d '{...}'   # -> 403

# clone/copy of an existing (or victim) object succeeds and yields the object
curl -s -X POST "https://$HOST/<object>/<SRC_ID>/copy" -H "$LOW_AUTH" \
  -d '{"<destination-field>":"<attacker>"}'                             # -> 200 + new object
```

When the source is another account's object AND the destination is caller-controlled,
this is the dual-authorizer hybrid — own it here / role-matrix, not idor-bola. Import/export ZIP flows can carry privileged embedded state (owner,
role, visibility) that the import route re-applies without a check — round-trip an
export, tamper the embedded fields, re-import, and read the result.

## Direct status transition (skip approval)

```bash
# UI forces draft -> pending-approval -> published; hit the terminal state directly
curl -s -X PATCH "https://$HOST/api/reports/<ID>" -H "$LOW_AUTH" \
  -d '{"status":"published"}'      # oracle: 200 + canonical read shows published
```

## High-value patterns

- create a restricted object by cloning an allowed/victim object;
- set the terminal status directly without passing approval;
- submit/review/close/delete reports without the role;
- create policy/update/comment/attachment for an unauthorized program;
- switch ownership of an attachment/file/application, then read via the new relation;
- bypass a subscription tier for project visibility or a premium feature
  (server never enforces the tier the UI hides);
- restricted staff updates customer/company records;
- low actor creates referral/POS-lead/opportunity;
- import/export flow preserves privileged embedded state.

## Good evidence

- the restricted transition persists and is visible to the allowed actor;
- audit/log shows the low actor performed the restricted action;
- UI/docs show the transition is restricted (negative control);
- the alternate route (clone/import/direct) succeeds while the canonical route denies.

## False-positive gates

- draft/local-only state that never reaches the server;
- action intentionally allowed to all collaborators;
- 200 in the response but a canonical read shows no persistence.
