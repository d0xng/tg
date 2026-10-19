# Authoritative XSS Research Sources

Use these sources to resolve specific browser, parser, API, sanitizer, or policy behavior observed during a target assessment. Do not copy payload lists blindly; connect each source to the actual source-to-sink path, browser behavior, framework version, and control being tested.

## Context and output encoding

- PortSwigger Web Security Academy, [Cross-site scripting contexts](https://portswigger.net/web-security/cross-site-scripting/contexts) — classifying HTML, attribute, JavaScript, and other reflection contexts before constructing a proof.
- OWASP Cheat Sheet Series, [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — context-specific output encoding, safe sinks, sanitization, and dangerous contexts.
- PortSwigger Web Security Academy, [Exploiting cross-site scripting vulnerabilities](https://portswigger.net/web-security/cross-site-scripting/exploiting) — impact paths and validation framing after execution is established.

## DOM sources, sinks, and browser APIs

- PortSwigger Web Security Academy, [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) — tracing attacker-controlled sources to execution sinks and validating in the live browser DOM.
- PortSwigger Web Security Academy, [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based) — broader source/sink families, web messages, URL manipulation, storage, and client-side gadget analysis.
- MDN, [`Element.innerHTML`](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML) — HTML parsing behavior, injection-sink risk, event-handler execution, shadow-root considerations, sanitization, and TrustedHTML assignment.
- MDN, [`HTMLScriptElement.src`](https://developer.mozilla.org/en-US/docs/Web/API/HTMLScriptElement/src) — dynamic script resource URLs and TrustedScriptURL behavior.
- PortSwigger Web Security Academy, [Client-side template injection](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection) — framework expression contexts that may escape to JavaScript execution.

## Web messages

- MDN, [`window.postMessage()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) — exact `targetOrigin`, receiver-side `origin` and optional `source` validation, and message syntax validation.
- PortSwigger Web Security Academy, [Controlling the web message source](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source) — practical origin-check failures, window relationships, and message-to-sink exploitation analysis.

## Sanitizers, mutation XSS, and parser differentials

- DOMPurify, [official repository and documentation](https://github.com/cure53/DOMPurify) — supported environments, configuration, hooks, Trusted Types integration, and the requirement to keep the sanitizer current.
- PortSwigger Research, [Bypassing DOMPurify again with mutation XSS](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss) — sanitizer/browser parser differentials and DOM mutation as a research methodology.

## Blind observation service

- XSS.Report, [official service page](https://xss.report/) — current blind-XSS platform and the evidence types its collector supports. The preserved channel path is `//xss.report/c/d0x/`; use a unique `src` tag per controlled injection point and follow the safety boundary in `callback-setup.md`.

## CSP, Trusted Types, and gadget chains

- MDN, [Content Security Policy guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP) — nonce, hash, strict CSP, deployment, reporting, and policy behavior.
- MDN, [`Content-Security-Policy: script-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src) — script sources, inline execution, evaluators, hashes, nonces, and `strict-dynamic` semantics.
- W3C, [Trusted Types](https://www.w3.org/TR/trusted-types/) — injection sinks, TrustedHTML and TrustedScriptURL, default policy behavior, enforcement, and the distinction between trusted provenance and safe content.
- PortSwigger Research, [Bypassing CSP via DOM clobbering](https://portswigger.net/research/bypassing-csp-via-dom-clobbering) — named-property clobbering as a gadget against trusted script-loading logic.
- PortSwigger Web Security Academy, [Content Security Policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) — CSP testing and bypass categories in web applications.
- PortSwigger Web Security Academy, [Client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution) — attacker-controlled properties reaching DOM XSS gadgets and source/sink analysis.

## Research discipline

Prefer current browser specifications, MDN API documentation, the exact sanitizer or framework's official documentation, and reproducible browser evidence. Record source title, URL, access date, affected version, tested browser, and the precise proposition the source supports. Treat offensive research as a hypothesis generator and independently reproduce the behavior within the program's scope.
