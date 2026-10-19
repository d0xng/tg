# File write -> RCE — Perforce chain + the loaded-path escalation ladder

A write primitive is only RCE when the path is **loaded/executed**. This file turns
an arbitrary/traversal write into a fired command. Prove the write on a **sentinel
path you own** first; land `id` only through a benign, owned, loaded path — never
overwrite a real system file on prod. Grounded in public Perforce
arbitrary-file-write research.

## The Perforce chain (arbitrary file write via a malicious server)

When the target integrates Perforce (P4) for version control / asset sync, the P4
client can be pointed at a server you control, and the server's `client-WriteFile`
message writes files to the client host.

1. Stand up a malicious Perforce server (respond to the P4 protocol, or use a public
   rogue-p4d PoC).
2. Coerce the client to connect — a `P4PORT`/config field you control, mDNS/Bonjour
   spoofing on the LAN, or a "connect to depot" feature that takes a host.
3. On sync, send `client-WriteFile` with a target path. **Key check:** if
   `P4CLIENTPATH` is **unset**, the client writes **anywhere** on the filesystem
   (no path confinement) — write to a loaded path -> RCE.
4. Loaded-path targets (below) -> code runs on next load/startup/login.

`P4CLIENTPATH` set to a confined root = mitigated (writes stay in the workspace).
The finding is "server writes outside the workspace"; prove with a sentinel path.

Same shape applies to any **attacker-controlled write path**: Zip-Slip
(`../../../` archive entries), path-traversal upload (`filename=../../x`), an
"export to path" field, a backup/restore that honours embedded paths, a
Git/SVN hook sync.

## The loaded-path escalation ladder (write -> code exec)

Pick the target that the runtime actually loads:

**Linux / app servers**
- **Webshell in webroot** — write `x.php`/`x.jsp`/`.aspx` into `/var/www/html`,
  the app's public dir, or a static-assets mount -> request it -> exec. (Use your
  **own** tenant's webroot for the `id` proof.)
- **`~/.ssh/authorized_keys`** — append your pubkey -> SSH in. (Prove the write to
  a sentinel, don't actually log in on prod at all — that requires d0x's approval before execution.)
- **Cron** — `/etc/cron.d/x`, `/var/spool/cron/crontabs/<user>` -> command on
  schedule.
- **`~/.bashrc` / `~/.profile` / `/etc/profile.d/x.sh`** -> exec on next shell.
- **systemd** — a `.service` in `/etc/systemd/system` + a reload trigger.
- **Language autoload** — a `.pth` in Python `site-packages` (runs on interpreter
  start), a `sitecustomize.py`, a Node `NODE_OPTIONS`/`--require` file, a Ruby
  `.rb` on the load path.
- **Config that runs code** — `.env` consumed by a worker, a nginx/apache conf
  `include` (-> see `k8s-ingress-config.md`), a supervisor program.
- **Git hooks** — write `.git/hooks/post-checkout|pre-commit|post-merge` in a repo
  the CI/app operates on -> runs on the next VCS op (-> `cicd-build.md`).

**Windows**
- **DLL hijack** — write a malicious DLL to a directory earlier in the app's DLL
  search order (app dir, `PATH` entry, WinSxS) -> loaded on next start. This is the
  classic Perforce-write -> DLL-hijack chain.
- **Startup/Run keys**, a `.lnk` in Startup, a `.bat` a scheduled task runs.

## Proof (rung-appropriate)

1. **Prove the write primitive** — write `__poc_<rand>__` to a **sentinel path you
   own / a non-loaded path**, then read it back (via the app, a listing, or a second
   request). This proves arbitrary write without executing anything. Confirm the
   path is arbitrary (write to two different dirs).
2. **Land `id` on a benign owned loaded path** — write a minimal
   `<?php echo shell_exec('id'); ?>` into **your own tenant's** webroot and request
   it once. Reflected uid = the RCE proof. Delete the file after.
3. **Do NOT** overwrite a real system file, real `authorized_keys`, a shared DLL, or
   anything another tenant/user loads. If the only loaded path is a real shared file,
   **state the chain by inference** from the proven arbitrary write and **d0x's approval before execution**
   before any prod overwrite (rung 5).

## Oracle / evidence

- **Confirm:** sentinel file written to an out-of-workspace / arbitrary path and read
  back; the owned webshell returns `id` output; the write lands at an
  attacker-chosen path (not confined).
- **Negative control:** the write is confined to the workspace / rejects `../`; a
  path outside the allowed root returns an error.
- **Not a finding:** write confined to a sandbox/tmp that is never loaded; `P4CLIENTPATH`
  set (writes stay in-workspace); a path that traversal-normalises away before the
  write.

## Safety

- Sentinel + owned-webroot only; delete PoC files after proving.
- No overwriting real system/other-tenant files, no persistence, no reverse shell.
- Revert every file you created. Capture path + uid/context; state escalation by
  inference. High/Critical -> `validation`.
