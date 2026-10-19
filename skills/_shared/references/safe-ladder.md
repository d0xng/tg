# The Safe-by-Default Impact Ladder

## Contents

- [Claiming a CVE — the version is rung 0, the fired oracle is the finding](#claiming-a-cve--the-version-is-rung-0-the-fired-oracle-is-the-finding)
- [Rung 1 — Read-only first (almost everything lives here)](#rung-1--read-only-first-almost-everything-lives-here)
- [Rung 2 — Your own / anonymous / self-created context](#rung-2--your-own--anonymous--self-created-context)
- [Rung 2b — Metered / billed actions (cost-amplification proofs)](#rung-2b--metered--billed-actions-cost-amplification-proofs)
- [Rung 3 — Prove the scale, don't hoard it](#rung-3--prove-the-scale-dont-hoard-it)
- [Rung 4 — Respect the RoE boundary literally](#rung-4--respect-the-roe-boundary-literally)
- [Rung 5 — Writes / state changes / financial / other-user data on prod](#rung-5--writes--state-changes--financial--other-user-data-on-prod)
- [Nothing will stop you — the rung is decided before the request is sent](#nothing-will-stop-you--the-rung-is-decided-before-the-request-is-sent)
- [Anti-patterns — phrasings a skill must NEVER produce](#anti-patterns--phrasings-a-skill-must-never-produce)

Shared reference. Every exploitation skill imports this instead of re-inventing
a "keep it passive" rule of its own.

**This is a ladder to REACH impact, not an excuse to avoid it.** A leaked secret,
an unauthorized endpoint, a bypassed check, a reachable SSRF sink — none of these
are findings on their own. The finding is the *proven impact*. Programs pay for
demonstrated impact, not discovery. So you MUST climb until the impact is proven.

The ladder tells you *how far* to climb and *in what order*, so that legitimate
verification is safe and non-destructive — NOT whether to climb at all. **Escalate only as far as needed to prove the bug —
but DO reach it.** Stopping one rung below proof is the failure this file exists to
kill.

Read the rungs top-to-bottom. Take the lowest rung that proves the class, then
stop. If the class is only provable higher, keep going — up to rung 5, where the
rule is to ask d0x directly before execution, not emit a blocker token or abandon
the target.

---

## Claiming a CVE — the version is rung 0, the fired oracle is the finding

A CVE id is a **label on a technique**, never evidence about *this* target. Two
separate failures, and both cost:

1. **Wrong id.** CVE numbers carry no meaning you can reason from — you cannot
   derive that a servlet accepting base64+gzip Java bytes is "54253" rather than
   "54254". Recall of id-to-technique mappings is unreliable, worst of all inside a
   family of sequential ids from one bulletin. **Never write a CVE number from
   memory. Read the vendor advisory or the GitHub Security Advisory, confirm the id,
   the affected range and the fixed version, or ship the technique with no number.**
   A mismatched id makes a triager read the whole report as unverified, and citing a
   CVE also claims a *known* bug — mislabel your own novel finding and you have
   duplicated yourself against the vendor advisory.

2. **Right id, target not actually vulnerable.** This is the expensive one. A
   version banner, a `<meta generator>`, a matching release number: all rung 0.
   Programs close these as informative — d0x has two of them, an Apache HTTP/2
   double-free filed on two different hosts, both stating "confirmed via version
   fingerprinting only", both informative, both zero bounty.

**So a CVE-based finding needs three things, and the middle one is the finding:**

- the fingerprint that says the product and version are in range (rung 0, free);
- **a non-destructive oracle fired against that exact endpoint** — the differential
  response, the error body, the timing delta, the OOB callback, the reflected read.
  This is what makes it real, and it is what you report;
- the safe proof at the lowest rung that demonstrates impact.

If the vulnerable code path is unreachable, the config mitigates it, or you cannot
make the oracle fire, then the target is **not** vulnerable — say that and move on.
"Version X is affected by CVE-Y" with nothing fired is not a finding, and reporting
it burns credibility you need for the next one.

## Rung 1 — Read-only first (almost everything lives here)

The cheapest non-mutating call that proves the primitive works AND what it
authorizes. Do this first, always. It is usually enough to make the finding real.

- Mint the token / trigger the primitive, then **read back its granted scopes**.
  "This secret is live and over-privileged" is itself a reportable fact.
- Call a **non-PII endpoint**: project/config/settings, catalog/published data,
  a `count`, your own test record, `/me` on a session **you** created.
- For SSRF: hit your **own OOB listener** and read back the reflected response /
  metadata you are authorized to reach.
- For IDOR/BOLA the *read* is rung 1 only when both objects are yours and you are
  reading your own data. The moment the proof needs a **second account acting on the
  first account's object** — which is the normal cross-account proof — it is **rung 2**
  (see below), and that is the number `validation` and
  `../../validation/references/severity-anchors.md` key off.
  Do not file the same act under two rungs.

If rung 1 proves the class, you are done. Do not climb higher "to be thorough."

## Rung 2 — Your own / anonymous / self-created context

When rung 1 can't show the action, demonstrate it against something you own:

- a session, cart, anonymous token, org, or test account **you created**;
- your own second account for the cross-object read;
- an anonymous/unauthenticated request where that IS the vulnerable state.

**Never another real user's context.** The proof uses objects you are entitled to.

## Rung 2b — Metered / billed actions (cost-amplification proofs)

When the missing control is an **entitlement / metering / quota** gate, the proof
is that a billable action *ran* for an identity that was not entitled to it. That
action spends the target's money, so it is bounded harder than a read.

- Run it on **your own free/consumer account** (rung 2) — never a victim's session.
- **The bound is 2–3 invocations.** Read the balance/quota, invoke once, read it
  again, invoke again: the meter that did not move IS the proof. Nothing beyond
  that adds severity.
- **Never bulk-generate to "show scale."** N free generations is not N times the
  finding. Scale is stated by inference from the published price of the plan you
  bypassed.
- **The severity anchor is the vendor's own document**, not the request count —
  quote the pricing/docs page stating the feature costs credits or requires a plan.
- Anything that would bill a **victim tenant** (a foreign org id in the header)
  stops at ONE invocation, and only after the read-side cross-tenant proof exists.
- If the action queues shared infrastructure work (renders, jobs, sends, emails),
  stop at the first sign of queue pressure and state the amplification factor by
  inference. Degrading availability is out of bounds even in scope.

## Rung 3 — Prove the scale, don't hoard it

**Mass PII exposure is one of the highest-paying classes there is. Chase it first,
not last.** Nothing on this ladder is a reason to walk past it, soften it, or
downgrade it. When an endpoint leaks other users' data, your job is to establish
**how much** — because the number is what makes it Critical instead of Medium.

**Never undersell the finding.** "I read one record" is a Low. "This endpoint
returns 1,847,392 customer records including email, phone and address; here is the
count, the pagination behaviour and a sample" is a Critical. Always report the
reach you demonstrated, not the volume you happened to download. If you could
have pulled the table, say so and prove it — do not describe a mass leak as if it
were a single-record bug.

**How to establish mass — every one of these is a demonstration, not a guess:**

- The envelope tells you: `"total": 1847392`, `"count"`, `X-Total-Count`,
  `hasMore`, `nextCursor`. Read it and report it.
- The limit is yours: raise `?limit=`/`?per_page=`/`?size=` and show the response
  grows with it. A server that honours `limit=1000` has no cap — that is the
  finding, and it is unbounded by construction.
- The range is populated: sample a spread of ids (first, middle, a high one) and
  show each returns a distinct real record. Three hits across the range prove the
  whole range, and the id space gives you the ceiling.
- A dedicated `count`/`stats`/`export` endpoint answers the question directly.
- Response size scales linearly with the requested page — measure it.

Report the number, the method you used to establish it, and enough sample rows to
make the shape undeniable. **Keep the raw capture in `notes/` where you can see
it; redact the values in the report but keep the field names, the count and the
Account-A-vs-Account-B contrast** — that is what a triager reproduces.

**The one line that does not move: do not bulk-download and store real third
parties' personal data.** Not because the class is off-limits — it is the class
you should be hunting — but because a report showing thousands of exfiltrated
records is grounds for removal from the program in most policies, and it converts
a Critical payout into a ban. Establishing that a million records are reachable
pays. Holding a million records does not pay more, and costs the program.

So: prove unbounded, state the real number, show the sample, stop pulling.

## Rung 4 — Respect the RoE boundary literally

If the program restricts horizontal-privesc / privacy / cross-tenant /
service-degradation testing to **UAT/OAT** hosts:

- Do those proofs **on the UAT/OAT instance** (`*-uat`, `*-oat`, staging), not
  prod. Find or seed that instance and demonstrate cross-tenant / PII there in full.
- **On prod, stop at a non-PII proof** that the primitive exists (rungs 1–2) and
  **state the prod-equivalent impact by inference**. "The same call on prod returns
  tenant B's records; demonstrated on UAT, withheld on prod per RoE" is a complete,
  payable proof.
- Reaching the impact on the *allowed* host is still reaching the impact. This rung
  relocates the proof; it does not cancel it.

## Rung 5 — Writes / state changes / financial / other-user data on prod

Password change, 2FA change, profile/data write, financial action, deletion, or
reading another **real** user's data on prod:

- **Pause and ask d0x directly before execution** (Non-Destructive Rules). Include
  the exact request, affected account/data/state, expected impact and rollback plan.
- If d0x explicitly approves and program policy and platform controls permit it,
  execute only the minimal proof and revert immediately. Approval for one exact
  request does not authorize broader mutation.
- If approval or required input is not yet available, keep working every independent
  safe angle. Do not turn the pending step into a terminal lead state or close the target.
- Prefer proving the same impact on UAT (rung 4) or by inference from a read
  (rung 1) so you never need this rung.

---

## Nothing will stop you — the rung is decided before the request is sent

There is no guard that refuses a step and tells you a line was crossed. **The rung
is a decision you make while writing the request, not a verdict you receive after
firing it.** Anything that reasons the other way round — "if it goes through, it
must have been allowed" — is the same silent false negative as a command that
errors and gets counted as a clean result. An absent guard never refuses.

So before the request leaves, name its rung. If it lands on rung 3-on-prod,
another user's PII, or a write, take one of these instead:

- non-PII read on prod (rung 1), or
- the full proof on UAT/OAT (rung 4), or
- ask d0x directly for approval, carrying exactly what you would run, what state
  it affects, how it will be reverted and the impact it would prove (rung 5).

Two consequences worth stating plainly, because nobody is watching the run:

- **A refusal you did not receive proves nothing.** The absence of a denial is not
  evidence the action was safe; it is evidence that nothing was checking.
- **The permission deny-list is a backstop, not the ladder.** It covers a handful
  of shell spellings. It does not know what a request means, and a destructive
  action it happens not to match is still a destructive action.

---

## A zero is not a negative until the command is proven to run

Three separate wrong conclusions in this pack's own history came from the same mistake: a command was run, it returned
nothing, and the nothing was read as evidence of absence. In every case the command was not doing what its author
thought.

- `rg -oh 'AKIA…'` — in ripgrep 14 `-h` is `--help`. The mandatory cloud sweep printed the help banner and exited 0
  for as long as it existed. Every "no cloud markers on this target" was unearned.
- `find . -newermt "-20 minutes"` — `find` on this host is `bfs`, which rejects that GNU date form. The syntax error,
  counted with `wc -l`, read as "no new files" while hundreds were arriving.
- A grep for `HTTP/1.1 200|captured:` over a lead directory returned zero, and "no lead has a captured response" was
  reported — the leads said `TEST STATUS — CONFIRMED LIVE` instead. Different wording, same false negative.

**So: before a zero-hit result becomes a conclusion, prove the command works.** Run it once against a control you know
contains the thing — a fixture file with a planted key, a file you just touched, a string you know is in the corpus. If
the control does not fire, the zero means nothing. This costs one command and it is the cheapest insurance in the pack.

State it in the finding too: "no markers found (sweep verified against a planted control)" is a real negative;
"no markers found" alone is not.

## Anti-patterns — phrasings a skill must NEVER produce

These are the "-safe timidity" tells. If your output is drifting toward any of
them, you have stopped one rung too early. Rewrite toward *proven impact*.

- "Don't call the API / don't use the discovered secret." — **Calling the API IS
  the deliverable.** Mint it and read scopes (rung 1).
- "Keep the proof passive / observe only." — A passive observation of a live
  credential is not a finding. Exercise it read-only.
- "Reject if the proof needs real data." — It doesn't need *other users'* real
  data; it needs *your own* context (rung 2) or a non-PII read (rung 1).
- "I read one record from another user, so this is a Medium." — **Undersold.** You
  established a leak; now establish its size (rung 3: `total`, a raised `limit`, a
  populated id range) and report the real number. A mass PII leak described as a
  single-record bug is a Critical you threw away.
- "Prove exposure minimally and hand off" — *minimally* means one record and
  read-only, **not** *never exercise it*. Minimal still reaches impact.
- "Report the finding as informational / potential / could-be-used-to." — Bug
  bounty pays for *proven*, not *potential*. Climb until you can drop "could."
- "Stop at discovery to stay safe." — Discovery is rung 0. Safety is *how* you
  climb (read-only, own-context, UAT), never a reason to skip the climb.
- "This is out of scope to verify." — If d0x handed you the asset it is
  authorized; scope is a safety boundary, not a hunting filter.

**The rule in one line:** take the lowest rung that proves the class, but always
take a rung that *proves the class*. Reaching impact safely is the job; stopping
short of impact is the bug this ladder fixes.
