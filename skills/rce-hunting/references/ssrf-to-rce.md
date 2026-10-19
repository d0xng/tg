# IAM creds from IMDS -> code-push -> RCE (the deploy-surface half of an SSRF chain)

An SSRF is not "just" an SSRF when the box runs in the cloud: the instance metadata
service hands out **IAM credentials**, and those credentials often reach a deploy
surface (CodeCommit, ECR, Lambda, S3 artifact buckets) whose next pull/deploy runs
your code -> **RCE in the deployment**. Reach IMDS with the `ssrf-safe` skill first
(bypass ladder, OOB confirm); this file is the metadata -> creds -> code-push half.
Hand the IAM exploitation to `cloud-exploitation`
(`../../cloud-exploitation/references/imds-metadata.md`,
`../../cloud-exploitation/references/iam-creds.md`).

## Contents
- Steps 1–2 — reach IMDS and pull the credentials (owned by `ssrf-safe`)
- Step 3 — Prove the creds (rung 1, read-only) — hand to cloud-exploitation
- Step 4 — The code-push -> RCE impact (rung 5 — state, don't fire)
- Oracle / evidence
- Safety

## Steps 1–2 — reach IMDS and pull the credentials

> **Owner:** `../../ssrf-safe/references/cloud-metadata.md` owns the endpoint catalog and
> reach mechanics for every provider (AWS IMDSv1/v2, ECS, Azure, GCP, DO/Alibaba/Oracle/
> OpenStack, k8s/loopback) plus the WAF-bypass encodings. Reach the sink with the
> `ssrf-safe` skill, aim it there, and come back here with the credential JSON.
> Honest grading of an IMDSv2-blind 401 (reach-only): `../../cloud-exploitation/references/imds-metadata.md`.

This file owns the half nothing else covers: **what those credentials do to a deploy
surface**, i.e. Steps 3–4 below.

## Step 3 — Prove the creds (rung 1, read-only) — hand to cloud-exploitation

The read-only proof, exactly like the k8s SA-token proof — this is the finding:

> **Tooling:** the `aws` CLI is not installed, but **`boto3` is** (1.43.18) and it does the SigV4 signing — so there IS an equivalent, contrary to what this file used to say. Run any AWS call as `python3 -c "import boto3,json;print(json.dumps(boto3.client('<svc>').<operation>(), default=str))"` with `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` exported. Install the CLI only if you want its ergonomics (`pipx install awscli`).

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity          # THE proof: whose creds, which account/role
aws iam list-attached-role-policies --role-name <role>   # scope, read-only
aws s3 ls                            # what buckets, read-only
aws ecr describe-repositories        # deploy surface, read-only
aws lambda list-functions            # deploy surface, read-only
aws codecommit list-repositories     # deploy surface, read-only
```

`get-caller-identity` + the read-only scope enumeration proves "these are live,
over-privileged, cloud IAM creds reachable unauthenticated via SSRF" — a complete
Critical. Read-only cloud enumeration belongs to `cloud-exploitation`
(`../../cloud-exploitation/references/iam-creds.md`) — hand it there and stop.

## Step 4 — The code-push -> RCE impact (rung 5 — state, don't fire)

If the role can write to a deploy surface, the next deploy runs your code:

- `aws codecommit put-file` / push to a repo a pipeline auto-deploys.
- `aws ecr get-login-password` -> `docker push` a malicious image to a repo whose
  task/pod pulls `:latest`.
- `aws lambda update-function-code` -> your code runs on next invoke.
- write to the S3 artifact bucket a CodeDeploy/CodePipeline stage pulls.

**All of these are writes / deploys -> rung 5.** Do NOT execute them on prod. State
the impact **by inference** from the read-only scope you proved in Step 3 ("the role
has `lambda:UpdateFunctionCode` on `<fn>`; the next invoke would run
attacker-controlled code -> RCE") and **ask d0x directly before executing** with the exact command if
a live code-push demo is genuinely required. Prefer proving it on UAT (rung 4).

## Oracle / evidence

- **Confirm:** the metadata endpoint returns creds; `sts get-caller-identity`
  returns a real ARN/account; scope enumeration shows deploy permissions.
- **Negative control:** the same SSRF to an external host returns normally; a random
  internal IP times out (proves you specifically reached the link-local metadata IP).
- **Not a finding:** IMDS reachable but the role has no useful permission (Medium
  reach-only SSRF); IMDSv2 enforced and the sink can't send the PUT-token header
  (blind SSRF, no creds).

## Safety

- Reading creds + `get-caller-identity` + read-only enum is rung 1 — do it.
- **No writes, no deploys, no code-push on prod** at all — that requires d0x's approval before execution (rung 5).
- Flag every credential you touched for **rotation** in the report.
- Hand the IAM half to `cloud-exploitation`; reach IMDS via the `ssrf-safe` skill.
