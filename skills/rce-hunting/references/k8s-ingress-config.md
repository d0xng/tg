# Kubernetes / ingress-nginx config injection -> RCE

A route/path/annotation reaches a generated controller config; a missed sanitiser
lets an attacker-controlled directive into `nginx.conf`, which the controller
reloads -> Lua/`nginx` execution. The headline class is **IngressNightmare**
(ingress-nginx admission bypass, CVE-2025-1974 + 1097/1098/24513/24514) reaching
`ssl_engine`/`auth-url`/snippet injection -> code exec on the controller ->
cluster-admin (the controller's SA can read every secret).

## Surfaces
- Ingress `path`, `host`, `rewrite-target`, `configuration-snippet` /
  `server-snippet` annotations, `auth-url`, `auth-snippet`, `ssl_engine`;
- generated nginx/apache/envoy config from a PaaS/control-panel route field;
- CRDs that render templates/config files;
- the admission webhook itself (unauth POST to `/validate` on the webhook pod).

## Concrete injection
An annotation that lands in `nginx.conf` outside its intended quoting:
```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: |
      access_by_lua_block { os.execute("id > /tmp/o") }
```
IngressNightmare (CVE-2025-1974): send a crafted `AdmissionReview` to the
controller's admission webhook that injects an `ssl_engine`/library-load directive
into the config it validates -> the controller loads it during validation -> RCE on
the controller pod **pre-auth from inside the cluster network**. The controller's
service account then reads all namespace secrets.

## Safe method (own-namespace = the proof)
1. Use a **local cluster / operator-owned namespace** for the destructive controller
   reload — a shared prod ingress reload can break every tenant's routing (that's the
   one place local/UAT is the *right* default, not timidity, because the payload is
   service-affecting).
2. Inspect the **generated config** for your controlled marker (`kubectl exec` the
   controller, read `nginx.conf`) — proves the injection without executing.
3. In your own namespace, prove the reload executes the marker (`os.execute("id")`
   -> read `/tmp/o`).
4. On a shared prod controller, stop at the **generated-config marker** (injection
   proven) + version fingerprint of a vulnerable ingress-nginx, and state the RCE by
   inference — do not fire a reload that breaks shared routing.

## Good evidence
- controlled field appears in generated config outside intended quoting;
- admission validation accepts the unsafe value;
- own-namespace/local controller executes the marker directive;
- the affected path crosses a namespace/tenant boundary.

## Not a finding / stop conditions
- value is escaped/quoted correctly in the generated config;
- snippet annotations are disabled (`allow-snippet-annotations: false`);
- proof would reload a shared prod ingress and break other tenants' routes -> use
  own-namespace/local, state prod impact by inference.

## Safety
- Own-namespace/local for the reload; generated-config marker on shared prod.
- The controller SA reads all secrets — treat any controller RCE as Critical, flag
  for rotation, `validation` before report.
