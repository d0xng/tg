---
name: xss
description: Hunt and validate reflected, stored, blind, DOM-based, postMessage, client-side template, mutation, and self-XSS chains. Use when attacker-controlled data reaches HTML, attribute, URL, JavaScript, template, message, navigation, code-loading, or DOM injection contexts; when filters, sanitizers, CSP, Trusted Types, or WAFs affect execution; or when JavaScript review exposes a source-to-sink path. Classify context and transformations before selecting a payload, create complete code-backed leads, and prove victim-context impact safely.
---

# XSS

Own the complete XSS class: reflected, stored, blind, DOM-based, web-message, client-side template injection, sanitizer/mutation bypass, DOM clobbering or prototype-pollution gadget chains, and self-XSS only when a concrete delivery mechanism reaches another controlled user or privileged renderer.

Do not begin with a payload list. Begin with the source, every transformation, the final parser or evaluator, the execution context, and the delivery path. A payload is correct only for the context that receives it.

Write all notes, leads, findings, and reports in English. Preserve code, requests, responses, identifiers, payloads, and browser evidence verbatim.

## Non-negotiable rules

- **Context before payload.** Determine where the value lands and which parser runs next: HTML text, quoted or unquoted attribute, URL-valued attribute, inline JavaScript string/template/expression, JSON hydrated into a client sink, CSS, SVG/MathML, markdown, framework template, DOM property, navigation, script URL, worker URL, or direct evaluator.
- **Measure transformations.** Record the value in the original request, raw HTTP response or stored object, parsed DOM, runtime variable immediately before the sink, and live DOM after the sink. Count decoding and encoding stages instead of saying only “it is encoded.”
- **Probe characters independently.** Start with a unique alphanumeric canary, then test the minimum context alphabet separately: `<`, `>`, `"`, `'`, `` ` ``, `&`, `/`, `\\`, `=`, `(`, `)`, `;`, `:`, whitespace, and the relevant URL-encoded and double-encoded forms. Record accepted, rejected, stripped, normalized, encoded, decoded, or mutated for each character.
- **Trace the complete path.** For client-side cases record `source -> decode/parse/normalize -> sanitizer/validator -> framework/helper -> sink/gadget`. A sink with a constant is not a lead; an attacker-controlled path into a sink is.
- **Separate execution from egress.** A local proof can execute while CSP blocks the external collector. For visible reflected or DOM testing, prove execution locally first. Use the OOB channel only when the render is blind, delayed, cross-user, or otherwise invisible.
- **Use the weakest harmless proof first.** Prefer an inert canary, a DOM marker, `console` evidence, or a visible local primitive. Use `alert(document.domain)` or an equivalent unmistakable execution marker only when needed. Never collect a real third party's cookies, tokens, DOM, storage, or PII; use accounts and objects controlled by d0x and stop at the policy boundary.
- **Do not confuse HTML injection with XSS.** Markup injection without JavaScript execution is a separate claim. Preserve it when it has concrete impact, but do not promote it as XSS.
- **A callback is not final impact.** A blind callback proves execution and context. Severity follows the demonstrated victim role, reachable actions or reads, persistence, scope, and delivery—not the word “blind,” “stored,” or “admin.”
- **Create complete leads early.** Every plausible code-supported source-to-sink, broken sender check, sanitizer/parser mismatch, or context-specific injection becomes a complete lead under `templates/lead.md` before live validation. A confirmed execution becomes a finding only after validation and impact calibration.

## Required first pass

1. Read the program policy, scope, controlled accounts, and existing target state.
2. Identify the exact source and delivery mechanism: query, path, fragment, header, cookie, form field, JSON, GraphQL variable, stored profile/object, API response, storage, `window.name`, referrer, web message, broadcast channel, service worker message, or polluted property.
3. Place a unique canary and capture every occurrence without assuming they share a context.
4. Build the character and transformation matrix from request through runtime.
5. Identify the parser or evaluator that consumes the value and the surrounding syntax needed to keep the document or program valid.
6. Classify the mode and open only the references routed below.
7. Construct the smallest context-correct proof, positive control, discriminating control, negative control, delivery proof, and safe stopping point.
8. Persist the complete lead and continue reviewing sibling parameters, renderers, routes, bundles, and components that share the same helper or sink.

## Mode router

- **Any reflected or stored server response:** read `references/discovery-context-encoding.md`, then `references/reflected-xss.md` or `references/blind-and-stored.md` according to the render path.
- **Any DOM or JavaScript source-to-sink path:** read `references/dom-xss.md`. Also read `references/postmessage.md` when the source is a web message, channel, popup, iframe, or opener.
- **Encoded, stripped, sanitized, normalized, or mutated input:** read `references/sanitizers-mxss.md` before declaring the sink safe.
- **CSP or Trusted Types blocks or changes behavior:** read `references/csp-trusted-types.md`. Keep execution bypass separate from callback/exfiltration egress.
- **Correct payload blocked by a WAF or filter:** read `references/bypasses.md` after the context and parser are already known. When a proven seed would accelerate testing, load `references/waf-bypass-payloads.txt`, select only entries compatible with the observed grammar, replace external domains or sensitive reads with controlled markers, and derive the smallest target-specific variant.
- **Blind, delayed, stored, staff-viewer, log-viewer, email-viewer, or renderer case:** read `references/blind-and-stored.md`, then its routed `injection-points.md`, `callback-setup.md`, `payloads.md`, and `escalation.md` references. The preserved d0x channel is `//xss.report/c/d0x/`.
- **Self-only execution:** read `references/self-xss-delivery.md`. Do not report self-XSS without a concrete victim-delivery or cross-user render path.
- **Need payload construction after context is known:** read `references/payloads.md`. Treat every vector as a hypothesis requiring browser proof, not a universal string.
- **Need authoritative behavioral baselines:** read `references/research-sources.md` and open the specific primary source relevant to the observed browser behavior.

## Context decision table

| Observed final context | First question | Route |
| --- | --- | --- |
| HTML text between elements | Can `<` create a node, and what survives parsing? | discovery + reflected or stored |
| Quoted attribute | Can the matching quote survive, can a new attribute be created, and is the element focusable/event-capable? | discovery + payloads |
| Unquoted attribute | Which whitespace, `>`, quotes, backticks, or equals signs terminate or extend the attribute? | discovery + payloads |
| `href`, `src`, `action`, navigation, script or worker URL | Who controls the scheme, authority, path, fragment, and final canonical URL? | discovery + DOM + CSP/Trusted Types |
| Inline JavaScript string or template literal | Which delimiter, escape routine, line terminator, expression position, and following syntax apply? | discovery + payloads |
| JSON or serialized state | Is it only data, or is it later parsed, assigned to HTML, evaluated, or used as a code/resource URL? | discovery + DOM |
| `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `srcdoc`, `document.write`, `DOMParser` | What attacker source reaches the parser, and which sanitizer or Trusted Types policy intervenes? | DOM + sanitizers |
| `eval`, `Function`, string timer, script text, dynamic code loader | Can the attacker control executable grammar after transformations, and does CSP permit the evaluator? | DOM + CSP/Trusted Types |
| `postMessage` or channel event | Can an attacker obtain the target window, pass sender checks, satisfy the message schema, and reach a sink? | postMessage + DOM |
| Framework raw-HTML/template escape hatch | Which framework/version, sanitizer, template compiler, hydration step, and downstream native sink apply? | DOM + sanitizers |
| HTML injection with CSP blocking script | Is there a DOM-clobbering, trusted-script gadget, unsafe URL, form, base, or same-origin loader path? | sanitizers + CSP/Trusted Types |

## Proof and control requirements

- **Positive control:** show the intended feature, renderer, message handler, or sink works with a benign value in the same session and state.
- **Character control:** show which exact delimiter or control character changed parsing and which did not.
- **Context control:** demonstrate the same canary in raw response, parsed DOM, runtime sink input, and final DOM whenever those stages exist.
- **Execution control:** use a local marker that proves JavaScript executed in the expected origin without relying on external network access.
- **Delivery control:** prove a controlled second account, controlled tenant, shared object, iframe/opener harness, or delayed renderer receives the attacker-controlled value.
- **CSP/Trusted Types control:** preserve console violations and distinguish enforced headers from `Report-Only`, inline execution from external script loading, evaluator blocking from HTML parsing, and execution from exfiltration.
- **Negative control:** use a benign value or a sender/origin that should be rejected and confirm the security-relevant behavior differs.

## Lead and evidence requirements

Every XSS lead must identify the exact source, endpoint or JavaScript file and line, transformation chain, reflection or render context, character matrix, sanitizer/filter/CSP/Trusted Types state, exact sink or gadget, payload rationale, delivery path, execution origin, affected role, priority rationale, controls, safe next steps, and the evidence needed to confirm or refute the claim.

For reflected XSS, include a victim-deliverable URL or exact request construction. For stored or blind XSS, include the plant request, storage object, likely renderer, per-point tag, timestamps, callback origin, and controlled-user proof. For DOM XSS, include the complete source-to-sink trace and runtime value immediately before the sink. For `postMessage`, include the attacker harness, target window relationship, message shape, sender-check analysis, and downstream sink. For sanitizer or CSP bypass, include the before/after DOM and the exact control that was defeated.

Store bulky raw material under `targets/<program>/notes/`. Use `templates/lead.md` for the actionable lead, `validation` before any High/Critical finding, and `report-writing` after validation.

## Handoffs

- `js-source-to-sink` owns complete JavaScript coverage and supplies code-backed source-to-sink leads; `xss` owns browser-context proof and XSS-specific bypasses.
- `auth-flow-bypass` owns OAuth/session protocol defects discovered while assessing an XSS chain.
- `tenant-isolation`, `broken-access-control`, and `idor-bola` own direct authorization flaws revealed by an XSS-accessible endpoint.
- `ssrf-safe` and `rce-hunting` own renderer-side URL fetch, file-read, template, or code-execution chains after the browser primitive is established.
- `validation` owns final validity and severity; `report-writing` owns the report.

**Completion rule:** do not close an XSS lead because one payload was encoded, one tag was stripped, one callback failed, or CSP logged a violation. Close only after the exact context, transformations, parser, sender checks, sanitizer/policy behavior, reachable gadgets, delivery path, and discriminating controls have been examined and persisted.
