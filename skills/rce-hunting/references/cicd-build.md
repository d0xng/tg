# CI/CD and build-hook RCE

Untrusted input (a PR from a fork, an imported repo, a package field, a webhook)
reaches a CI/build run step and executes. The finding is a **marker command that
ran in the pipeline** — printed to a CI log **you can read**, or an artifact **you**
created. Own-context (your own fork/repo/project) is the legitimate proof surface
here — that's rung 2, not a "local repro fallback".

## Surfaces
- GitHub/GitLab "import repo", PR/MR workflows that run on `pull_request` from forks;
- `workflow_call`, composite/reusable actions, `pull_request_target` (runs with
  secrets on untrusted PRs);
- package scripts: `preinstall`/`postinstall`/`prepare`, `npm`/`pip`/`gem` build hooks;
- deploy commands in `Makefile`, npm scripts, `setup.py`, Gradle/Maven, Dockerfile;
- preview-environment builders; import jobs that run repo-controlled hooks.

## The classic sinks (concrete)

**GitHub Actions script injection** — untrusted field interpolated into `run:`:
```yaml
- run: echo "PR title: ${{ github.event.pull_request.title }}"
```
A PR titled `"; id; echo "` (or issue body, branch name, commit message) breaks out
of the shell string -> exec on the runner. High-value untrusted contexts:
`github.event.*.title/body`, `head_ref`, `pull_request.head.ref`,
`*.commits.*.message`, `review.body`. Proof: title the PR to `echo <nonce>-$(id)`,
read your own PR's Actions log for the marker + uid.

**`pull_request_target` with checkout of PR head** — runs privileged (has repo
secrets) but checks out attacker code -> the PR's `postinstall`/build script runs
with `GITHUB_TOKEN`/secrets -> exfil/RCE. This is the high-severity variant.

**postinstall hook** — a `package.json` you control (dependency, PR) with
`"postinstall": "node -e \"console.log(require('child_process').execSync('id').toString())\""`
runs on the target's `npm install`.

## Safe method (own-context = the proof)
1. Use **your own** fork/repo/project/PR — never poison a shared/protected branch.
2. Prove the untrusted field reaches a `run:` step (read the workflow file; confirm
   the interpolation).
3. Fire a **benign marker**: `echo <nonce>-$(id)` / write an owned artifact. Read it
   back from the CI log/artifact **you** have access to.
4. Do NOT exfiltrate the target's secrets/`GITHUB_TOKEN`/env — the marker + uid is
   the proof. If the runner has secrets by design (`pull_request_target`), that IS
   the impact — state it; do not dump the secrets.
5. If firing would touch a production/protected pipeline with real secrets, prove on
   your own fork and state the prod-equivalent impact.

## Good evidence
- untrusted PR/fork/package field reaches a run step (shown in the workflow);
- CI log shows your marker + `id` executed on the runner;
- workflow runs in a privileged context / with secrets available by design;
- import job executes repo-controlled hooks.

## False-positive gates
- workflow not used by any protected branch / release path;
- runner has no sensitive permissions and is documented as untrusted throwaway;
- execution needs a maintainer to manually run arbitrary code outside the workflow.

## Safety
- Own fork/repo only; benign marker only; no secret exfil, no persistence.
- Don't tamper with shared runners or other contributors' pipelines.
- High/Critical (privileged runner, secret access, supply-chain reach) -> `validation`.
