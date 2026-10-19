# CSP and Trusted Types

Use this reference after an injection or source-to-sink path is established and an enforced browser policy changes execution. CSP and Trusted Types are mitigation layers and diagnostic signals; they do not erase the underlying injection, and bypass claims require a concrete policy-specific gadget.

## Separate four questions

1. **Did attacker-controlled data reach an injection sink?** Preserve the source-to-sink path independently of policy.
2. **Did JavaScript execute locally?** Use a local marker that does not require external network access.
3. **Could attacker-controlled code or a trusted gadget execute under the enforced policy?** Analyze script/evaluator/URL controls.
4. **Could evidence leave the page?** Analyze `connect-src`, `img-src`, `form-action`, `style-src`, navigation, and other egress separately.

A missing xss.report callback answers none of these questions by itself.

## Capture the effective policy

- Distinguish `Content-Security-Policy` from `Content-Security-Policy-Report-Only`.
- Capture every CSP header; multiple enforced policies apply together rather than one replacing the others.
- Capture relevant `<meta http-equiv>` policies and note that they may differ from headers and apply only after their position in the document.
- Compare the exact vulnerable response, not only the site home page. Error pages, legacy routes, previews, downloads, and alternate hosts may use different middleware.
- Preserve console violations and the blocked directive/source.

Record at least `default-src`, `script-src`, `script-src-elem`, `script-src-attr`, `object-src`, `base-uri`, `connect-src`, `img-src`, `style-src`, `frame-src`, `frame-ancestors`, `form-action`, `worker-src`, `navigate-to` when supported, `require-trusted-types-for`, and `trusted-types`.

## Execution behavior

- Inline script and inline event handlers are normally blocked by an enforced `script-src` or fallback unless an applicable nonce, hash, or unsafe allowance exists.
- `eval`, `Function`, and string timers are controlled separately through evaluator policy such as `unsafe-eval`; do not infer evaluator behavior from inline-handler behavior.
- External script and module loading is controlled by source expressions, nonces/hashes, redirects, CORS for modules, and `strict-dynamic` trust propagation.
- Under `strict-dynamic`, trust can propagate from a nonce/hash-bearing root script to scripts it creates; host allowlists may be ignored by supporting browsers. A loader that builds a script URL from attacker data can therefore become the relevant gadget.
- A nonce visible in DOM is not automatically a bypass. Prove that attacker-controlled markup or a trusted gadget can use, copy, or launder it in the actual browser and policy.

## Policy-specific bypass categories

Investigate only categories whose prerequisites exist:

- Attacker control inside the CSP value or a parameter used to construct it.
- A same-origin or allowlisted endpoint that returns attacker-controlled JavaScript with a usable content type.
- JSONP or callback endpoints whose callback/value constraints permit executable grammar.
- Trusted framework/library gadgets that evaluate templates, create scripts, or compile strings under an allowlisted origin.
- A nonce/hash-bearing trusted loader that consumes attacker-controlled script URLs under `strict-dynamic`.
- Missing `base-uri` combined with relative trusted script URLs and a controllable base element.
- DOM clobbering that changes a trusted loader's script/worker/module URL.
- Nonce reuse, predictable nonces, nonce reflection into attacker-controlled markup, or unsafe server/client template substitution.
- A vulnerable route, alternate host, preview, or error response where the enforcing policy is absent or materially weaker.
- Policy injection that changes a more specific directive supported by the target browser.

Do not treat a broad hostname in `script-src` as exploitable without a concrete attacker-controlled script response on that host. Do not claim a library gadget without verifying the exact version and invocation syntax.

## Trusted Types

Record enforcement (`require-trusted-types-for 'script'`), allowed policy names, duplicate-policy rules, default policy creation, and every `createHTML`, `createScript`, and `createScriptURL` implementation. Trace attacker input into the policy and from the resulting trusted object into the sink.

Candidate weaknesses include a default policy that passes input through, weak URL allowlists, policy names any script can create, policy functions that call an unsafe or misconfigured sanitizer, attacker-controlled configuration or hooks, trusted values stringified and reparsed, sinks or browser paths outside the enforced group, and reviewed helper functions that create trusted values from data with unclear provenance.

When a sink throws a Trusted Types `TypeError`, preserve it as evidence that enforcement intervened. Then inspect policy creation and alternate sinks rather than assuming the source-to-sink path is exploitable.

## Egress and blind evidence

After local execution is proven, choose the least sensitive permitted evidence channel. The preserved blind collector is `//xss.report/c/d0x/`. Module import requires script loading permission and, for cross-origin modules, a compatible response. Image, beacon, fetch, form, stylesheet, navigation, and DNS evidence each depend on different directives and browser behavior. Use attribution-only markers by default and never exfiltrate real third-party secrets or data.

## Evidence checklist

- Exact vulnerable response and every enforced/report-only policy.
- Browser and version used for policy interpretation.
- Local execution result independent of egress.
- Exact directive that blocks or permits each attempted sink.
- Trusted script/library/loader gadget and all prerequisites.
- Trusted Types policy source, transformation, return type, and sink.
- Positive and negative policy controls.
- Minimal controlled impact and why the policy-specific technique is reproducible.
