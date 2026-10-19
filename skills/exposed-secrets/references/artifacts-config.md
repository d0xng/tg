# Artifacts, Config, And Backup Exposure

Use for exposed environment files, configs, backups, exports, object storage,
archives, build artifacts, CI logs, and deployment bundles.

## Common Files

- `.env`, `.env.*`, `config.*`, `settings.py`, `database.yml`, `web.config`;
- `docker-compose.yml`, kubeconfig, Helm values, Terraform state;
- `.bak`, `.backup`, `.old`, `.zip`, `.tar.gz`, SQL dumps;
- CI artifacts, build logs, reports, exported CSV/XLS/PDF/JSON.

## The whole build, in one file, at the webroot

The highest-yield single request in this file. Deploy scripts that `zip` the build
directory and copy it up frequently leave the archive **next to** what they unpacked,
so it is served as a static asset. One `GET` returns the entire production
application — not one bundle, all of them, plus the sourcemaps, plus whatever was in
the tree at build time.

```bash
for f in web dist build www site public app frontend client release backup deploy \
         "$(basename "$TARGET_HOST" | cut -d. -f1)"; do
  for e in zip tar.gz tgz tar rar 7z; do
    curl -sk -o /dev/null -w "%{http_code} %{size_download}\t/$f.$e\n" "https://$TARGET_HOST/$f.$e"
  done
done | grep -v '^40[0-9] \|^30[0-9] '
```

Judge it on **status + size together** — a `200` serving the SPA's `index.html`
fallback is the usual noise, and it is recognizable because every path returns the
same few kilobytes. A multi-megabyte `200` with `Content-Type: application/zip` is the
real thing. Confirm before pulling it with a ranged `GET` (`curl -sr 0-3000`) and read
the local file header rather than downloading blind.

**What makes it a report is never "an archive was downloadable"** — it is what the
archive hands you, and it is usually three things at once:

- **the complete route table.** Every API path the app can call, including the ones no
  UI reaches — password reset, mail send, transfer, proxy-update, presigned-upload.
  Test each one unauthenticated; in the corpus case several answered.
- **hardcoded keys** that bundle mining alone would have found, but also build-time
  files that never ship to the browser at all.
- **internal hostnames and ports** (`<name>.<internal-tld>:19000`, an internal object
  store, a docs host) — the map for everything after.

Route it: keys → `saas-key-exploitation.md`; internal hosts → `ssrf-safe` targets and
`ffuf-web-fuzzing` vhost candidates; unauthenticated routes → `broken-access-control`.

## Object storage is not only AWS

`s3.amazonaws.com` is the one everybody greps. The same public-listing mistake is made
on every other provider, and their hostnames look nothing like S3 — so a bundle sweep
tuned to `amazonaws` misses them entirely:

| Host shape | Provider |
|---|---|
| `<bucket>.oss-<region>.aliyuncs.com`, or a **vanity CNAME** like `oss.<company>.com` | Alibaba Cloud OSS |
| `<bucket>.cos.<region>.myqcloud.com` | Tencent Cloud COS |
| `<bucket>.blob.core.windows.net` | Azure Blob |
| `storage.googleapis.com/<bucket>`, `<bucket>.storage.googleapis.com` | Google Cloud Storage |
| `<bucket>.<region>.digitaloceanspaces.com` | DigitalOcean Spaces |
| `<bucket>.r2.cloudflarestorage.com` | Cloudflare R2 |
| `<host>:9000` / `<host>:19000` with `Server: MinIO` | self-hosted MinIO |

All of them answer a bare `GET /` on the bucket host with an XML listing when listing
is enabled — the same `<ListBucketResult>` / `<Contents><Key>` shape. **The vanity-CNAME
row is the one that hides**: `oss.<company>.com` reads like a first-party asset host and
is only recognizable from the XML it returns, so fetch the root of any asset host the
app references instead of assuming a CDN.

Count what listing gives you and say the number — an enumerable listing is what turns a
handful of sample documents into a mass-exposure claim, and per the severity ladder the
count is what separates Critical from Medium.

## Method

1. Capture path, status, size, last-modified, content type.
2. Fetch the file, grep it for secret shapes (`AIza`, `sk_live_`, `sb_secret_`,
   `BRAZE_REST_API_KEY`, `client_secret`+`.onmicrosoft.com`, DB/service creds,
   AWS keys). Redact secrets in leads.
3. **When a live credential appears, use it read-only to prove impact** — pivot
   to `saas-key-exploitation.md` (Braze/Google/Azure/Supabase/Stripe/dotCMS) or,
   for AWS/Cognito/S3/DynamoDB material, hand to `cloud-exploitation`. The exposed
   `.env`/backup is the delivery surface; the finding is the service/data/infra
   the credential unlocks (safe ladder rung 1: mint/validate, read scopes + one
   non-PII object).
4. Do not bulk-download the bucket/backup/dump — extract the specific secret,
   prove it, state the rest by inference.

## Good Evidence

- config contains a DB/cloud/API credential that **authenticates when exercised**;
- backup/dump contains source or user data reached via one bounded sample;
- Terraform/kubeconfig yields infra access material that mints a working token;
- public bucket/listing exposes an artifact carrying a live secret.
