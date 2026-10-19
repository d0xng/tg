# The plays — SSRF

Built from 16 of d0x's own reports on this class. Each play: the **shape** that transfers to any target, then the corpus case, with its outcome.

The severity distribution is the first thing to absorb: **11 Medium, 4 High, 1 informational, and no Criticals.** This class reliably produces Mediums. What separates the Highs from the Mediums in this corpus is never the bypass — it is whether the response came back and what it carried.

Refs point at `~/Desktop/skills/personal-corpus/`.

---

## 1 · The AI tool sink — five reports, the largest cluster

> **Shape.** An LLM feature fetches a URL server-side: an attachment validator, a multimodal `image_url` block, an agentic tool that downloads and stores, an MCP server tool. The fetch usually happens in the **harness**, before the model reasons about anything, so it is deterministic and independent of model safety.

This is the highest-yield SSRF surface in the corpus and it is where new sinks keep appearing. One program names it as a prioritized in-scope class in its own words — *model-induced SSRF via backend tools* — so it is worth checking whether the target's policy does too.

| ref | sink | reach | outcome |
|---|---|---|---|
| 3743869 | assistant tool taking a `presignedUrl` | full read; response reflected into chat history | Medium · triaged |
| 3745673 | agentic workflow action taking `input-images[].url` | cloud IMDS, in-pod loopback, bodies reflected on non-2xx | Medium · triaged |
| 3749657 | OpenAI-compatible `/v1/chat/completions` `image_url` block | k8s API server, cloud IMDS, 8+ loopback ports | Medium · triaged |
| 3896569 | three MCP tools: mime-type, short-url resolve, save-to-path | internal host, IMDS, **persists the fetched body** | Medium · new |
| 3764640 | MCP tool taking an `authorUrl` | **exfiltrates the caller's bearer token** | **High** · triaged |

**The one that scored High did something the others did not: it leaked a credential.** The MCP tool attached the caller's own `Authorization: Bearer` header to the outbound request to an attacker-named host. That converts SSRF into token theft, and the report notes the compounding factor — MCP servers are consumed by AI assistants, so the same sink is reachable through prompt injection against any user connected to it.

**What to check on every AI sink:**

- Does the fetch happen **before** the model sees the message? If yes, say so — it makes the finding reliable rather than probabilistic.
- Does the outbound request carry **the caller's credentials**? That is the High.
- Does a tool **persist** the fetched body somewhere the caller can read? One tool declared its input was a signed storage URL and accepted any unsigned URL, storing the complete response.
- Does the fetcher **follow redirects**? Demonstrated in two of these — a redirector defeats any allowlist applied to the initial URL, because validation is not bound to the final destination.

---

## 2 · The renderer that hands you the render

> **Shape.** A document, screenshot or thumbnail service fetches your URL with a real browser and returns the rendered artifact. The artifact **is** the response body. That is a full read, not a blind SSRF.

**3794880 · `*.acrobat.adobe.com` · High claimed → informative**

An HTML-to-PDF operation takes `{"url": "..."}`, renders it with server-side headless Chrome, and stores the PDF in the caller's own cloud storage. Only the scheme was validated — loopback, link-local, decimal, hex and IPv6 forms of the same address all accepted; `http://` and `file://` rejected. Rendering an internal-only corporate hostname returned the internal proxy's error page, naming that hostname, inside the PDF.

**It still came back informative.** The likely reading: the egress is a proxy the vendor considers a boundary, and no internal *content* was retrieved — only the proxy's own error. Worth knowing before spending a turn: a full-read primitive that only ever reads the proxy's refusal is still a proxy refusal.

**So when a renderer is the sink, the finding is not "it rendered my page."** It is a specific internal document the render brought back. Get one, or state clearly that you did not.

The bypass ladder in one line, from that report — all accepted where a host allowlist should have refused:

```
https://127.0.0.1/      https://localhost/       https://[::1]/
https://2130706433/     https://0x7f000001/      https://169.254.169.254/
```

---

## 3 · The protocol-relative URL that replaces the host

> **Shape.** A parameter is treated as a *path fragment* by the developer and resolved as a *URL* by the library. A value beginning with `//` is a protocol-relative URL, so it replaces the host entirely.

**3896313 · `abercrombie.com` · High · duplicate**

A component-name parameter on an undocumented GraphQL plane is resolved as a URL before the upstream fetch. `//<internal-host>/<path>` replaces the intended host, port and path, and the fetched body is returned in the response field. No authentication.

What it reached is why it is High rather than Medium: the internal account service, selectable by either email-derived id or user id, returning **stored password credential material with its salt**, plus name, email, phone, date of birth and address book.

**The enforcing sibling was in the report:** the identical operation on a different plane of the same BFF *does* enforce an exact-match allowlist on the same parameter. One plane has the control, the other does not.

**Try `//host/` on every parameter that ends up in a URL, even one that looks like a name or an id.**

---

## 4 · Path traversal into a fixed internal host

> **Shape.** The host is hardcoded and safe. The *path* is built by string interpolation from your input. You cannot choose the destination service, but you can choose any resource on it.

**3896906 · `abercrombie.com` · Medium · new**

An order identifier is interpolated into an internal URL path without encoding. Encoded `..` sequences escape the intended route to the internal service root; `?` and `#` injection control the query and fragment of the internal request; non-2xx internal bodies come back through the GraphQL error field.

The report names the class precisely — *a constrained or path-restricted SSRF primitive rather than arbitrary-host SSRF* — and bounds the claim: no records, credentials or secrets retrieved, the sink issues a `GET`, no internal state changed.

**This is worth reporting even though the host is fixed.** It is also a path-traversal finding, and stating both framings is what makes it hold.

---

## 5 · The document that carries its own URLs

> **Shape.** The server parses a structured document you supply and dereferences URLs **embedded inside it**. You never pass a URL parameter at all.

**3791331 · `*.acrobat.adobe.com` · Medium · resolved**

A certificate-validation endpoint accepts a base64 X.509 certificate and performs chain and revocation checking. During validation it fetches the **CRL distribution point** and **OCSP responder** URLs embedded in the submitted certificate. Both are attacker-controlled because the certificate is.

Two distinct sinks from one submission: the CRL URL is fetched with `GET`; the OCSP URL is fetched with `POST`, carrying a DER body — **an SSRF with attacker-chosen host, port, path *and* body.**

Reachable unauthenticated: the only credential is a static api key published in the web bundle.

**Generalise the shape, not the format.** Anything that parses a document and follows what is inside it is this play: XML with external entities, SVG, a feed URL, a manifest, an OpenID or JWKS discovery document, a webhook payload naming a callback.

---

## 6 · The connection tester

> **Shape.** A settings page offers to "test" a destination the user configured. Testing means connecting, and the result is reported back.

**3867160 · `*.mercadopago.com.ar` · Medium · duplicate** — FTP and webhook connection checkers accept RFC1918 literals directly. The oracle is sharp: a nonresponding private control returns `500` after 10–30 seconds; a live private service returns a checker-specific error in **0.4 seconds**. On one private host, one port answered fast and another timed out — a same-host port-state oracle.

**3741039 · `apps.goshippo.com` · Medium · informative** — a webhook is registered with a loopback URL, then the test endpoint is triggered; the error leaks the internal target's HTTP status code.

Note the split: the same class, one duplicate and one informative. **A port oracle alone is a Medium at best.** What the first report added was an out-of-band callback that arrived carrying internal client metadata, including a header declaring `admin` caller scopes.

**Testing discipline worth copying.** That report states its own bounds: *"Testing was deliberately limited to two named services learned from public DNS, one same-host port comparison, one nonresponding control, and one OOB callback. No subnet or port sweep was performed."* Learn the internal names from public DNS rather than sweeping.

---

## 7 · The unauthenticated form relay

**3856592 · `www.mercadolibre.com.ar` · Medium · triaged**

An unauthenticated form endpoint issues a server-side `POST` to an attacker-chosen destination with an attacker-controlled JSON body and one controllable outbound header — including the internal `x-source-ip` trust header, which downstream services may believe.

**Controlling an outbound *header* is worth calling out separately from controlling the URL.** If any internal service trusts a forwarded-IP or caller-identity header, an SSRF that can set it is an authorization bypass with extra steps.

---

## 8 · The parameter nobody validated

**ac6c76dc7bd2 · `axis os` · P3 · informational**

The endpoint validates its `address` parameter thoroughly — loopback in decimal, octal, hex, short-form, IPv6, all correctly blocked. The **`proxyaddress`** parameter on the same endpoint has none of that validation.

**When you find a well-defended URL parameter, enumerate the endpoint's other parameters before concluding it is safe.** A thorough denylist on one field is evidence the developer knew the risk, which makes an unguarded sibling field more likely, not less.

---

## The bypass ladder, as it actually worked here

Ordered by what succeeded in this corpus:

1. **Nothing at all** — most sinks had no host validation whatsoever. Try the plain internal literal first; five of these reports needed no bypass.
2. **Decimal / hex / IPv6 encodings** — `2130706433`, `0x7f000001`, `[::1]`, `0177.0.0.1`. Defeated a denylist outright in one report where the control *"provides zero protection against this trivial bypass."*
3. **Userinfo** — `https://allowed-host@attacker-host/path`. Defeated an allowlist, and there is a sting in the tail: the backend HTTP client converted the userinfo into an outbound `Authorization: Basic` header. Where a real credential feeds that position, it leaks the same way.
4. **Protocol-relative** — `//internal-host/path` in a parameter that is concatenated rather than parsed.
5. **A redirector you control** — defeats validation applied only to the submitted URL. Confirmed twice.
6. **A sibling parameter** — see play 8.

---

## Oracles — how these were confirmed without a response body

Most of this corpus is blind. The oracles that worked, and what each distinguished:

| oracle | signal | what it separates |
|---|---|---|
| **timing** | 0.4 s vs 10–30 s; instant NXDOMAIN vs 60 s hang | live service · filtered port · nonexistent name |
| **status reflected** | the internal status appears verbatim in the error | open port with an HTTP service |
| **client error strings** | distinct DNS / TLS / refused / timeout / HTTP messages | the exact failure stage |
| **MIME type returned** | content-type of the fetched resource | what is listening |
| **response size** | byte-count clusters | which tier answered |
| **out-of-band** | a callback lands | egress exists, and the headers name the caller |

**Always run the nonresponding control.** Every clean report here has one: a private address that does *not* answer, so the fast/slow split means something. Without it, a timing claim is unfalsifiable.

---

## What the callback carries — the second finding inside the first

Every out-of-band callback in this corpus arrived with internal headers, and they are worth reading rather than discarding:

- service-mesh metadata naming the **pod, internal IP, namespace and deployment**, and two callbacks from different pods proving a load-balanced deployment
- distributed-tracing ids exposing the observability stack
- an internal client identity header declaring **`admin` caller scopes**
- the internal egress proxy's own identity and error pages, naming internal hostnames

**Capture the full request at the collaborator, not just the fact that it arrived.**

---

## Where it reaches, and what that is worth

Confirmed across the corpus: cloud metadata endpoints on two providers, the Kubernetes API server, cluster DNS, in-pod loopback services bypassing the authenticating ingress, an internal corporate git host, an internal account service, and internal service-mesh admin ports.

But note what did **not** happen: **no report in this class extracted credentials from a metadata endpoint.** One reached the IAM credentials path and got a `200` through a blind oracle, and the report says exactly what that means and does not mean — *the role name cannot be extracted through this blind oracle, but the attack path exists* — then describes the chain that would be needed. That honesty is why it was triaged rather than discarded.

**So: reaching IMDS is not credential theft, and reporting it as such is how these get closed.** Reaching it *is* worth reporting, framed as reachability plus the named barrier that remains.

---

## The two frames that cost value here

**A blind oracle with no named internal target is a lead, not a finding.** Both `informative` results in this class are oracle-only findings. Learn one real internal hostname — from public DNS, from a leaked config, from an error message — before writing up.

**A full read that only reads the proxy's refusal is still a refusal.** Retrieve one internal document, or state plainly that the egress proxy stood in the way.
