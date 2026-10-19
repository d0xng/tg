# Dependency / supply-chain RCE

Docs/build/CI/lockfiles reference a package or namespace an attacker can claim; a
claimed package's install hook runs on the target's `install`/`build`/`deploy` ->
RCE on dev/CI machines. The finding is **proven claimability + a reachable install
path** — install-hook execution is demonstrated in **your own** test namespace/repo,
not by publishing malware to the target.

## Surfaces
- npm/PyPI/RubyGems/Maven/Go/Composer/Cargo package names in JS, lockfiles, docs,
  CI logs, error traces;
- **dependency confusion:** a private/internal package name resolvable from the
  public registry (`@company/internal-lib` with no public scope lock);
- install docs referencing unclaimed GitHub users/orgs/repos;
- `make`/deploy scripts that `git clone`/`curl | sh` an external repo;
- package scripts run during install/build/deploy (`postinstall`, `prepare`).

## Safe method (own-namespace proof, coordinate before claiming a real one)
1. **Prove claimability read-only:** the internal package name returns `404`/is
   unregistered on the public registry (`npm view <name>` -> not found; PyPI `GET
   /pypi/<name>/json` -> 404); the GitHub org/user is available (`404` on the
   profile + "username available" on signup). That is rung-1 evidence.
2. **Prove reachability:** the name appears in the target's lockfile/CI/docs, and
   the resolver would prefer the public registry (no scope lock / higher version).
3. **Prove the hook fires in YOUR OWN namespace:** publish a **benign** package
   under a **test name you own** with `"postinstall": "echo <nonce>-$(id)"`, install
   it yourself, show the marker. This proves the primitive without touching the
   target's registry entry.
4. **Do NOT publish under the target's real internal name / claim the real abandoned
   org** unilaterally — that would poison real installs. That step is rung 5:
   **ask d0x directly before executing** rather than claiming,
   with a benign beacon.

## Good evidence
- internal package name is installable from the public registry (claimability proof);
- docs/CI/deploy clone code from an unclaimed namespace;
- own-namespace test package's `postinstall` marker executed;
- the program confirms the affected build/deploy path consumes that dependency.

## Stop conditions / not a finding
- the name is scope-locked / already owned by the org (not claimable);
- the dependency is dev-only with no reachable build/deploy consuming it;
- proof would run on real developer machines or disrupt legitimate installs.

## Safety
- No publishing under the target's real names, no claiming real abandoned orgs
  without coordination; benign beacon only if authorised.
- Don't collect developer-machine data (env, tokens, IPs, filesystem) — nonce + uid.
- Confirmed reachable install path -> `validation`.
