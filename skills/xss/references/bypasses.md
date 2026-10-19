# Filter and WAF Bypasses — differential testing after context classification

Use this reference only after `discovery-context-encoding.md` establishes the final parser context and a context-correct local proof works without the suspected filter. The goal is to identify the exact validation or normalization mismatch, not to spray a payload encyclopedia.

## Local proven-payload corpus

`waf-bypass-payloads.txt` contains 181 payloads supplied by d0x that previously bypassed real filters or WAFs. It is a maintained seed corpus, not a blind spray list and not evidence that a technique still works in the current browser, parser, framework, or policy.

Load the text file only after identifying the final context, required delimiters, accepted characters, decoding stages, and suspected blocking signature. Select entries whose grammar matches those observations, then minimize or adapt them one property at a time. Replace `evil.com`, `test.bxss.in`, `X55.is`, or any other external host with d0x-controlled infrastructure; replace `document.cookie`, token, DOM, or storage reads with a harmless controlled canary unless the data and accounts are owned by d0x and program policy explicitly permits the proof.

The corpus may be maintained as new evidence arrives: preserve an original working line, append a minimized or target-specific variant only after browser validation, and record the relevant WAF/product, browser, final context, transformation, date, and target lead outside the text file. Do not delete an unusual encoding merely because it looks malformed; remove only confirmed exact duplicates or unusable corruption, and never silently generalize a target-specific bypass into a universal rule.

## Required model

Write the path as `input channel -> edge/WAF -> application decoder -> framework parser -> sanitizer -> serializer -> browser parser -> sink`. Record which component rejected or changed the value and whether the response came from the edge, application, or browser. A blocked string does not prove that the relevant characters or grammar are universally blocked.

For every bypass hypothesis, preserve a matched pair: one request that is blocked or neutralized and one request differing in only one meaningful property that reaches the same sink. Repeat the pair enough to distinguish deterministic filtering from rate limits, bot controls, cache variance, or unstable application behavior.

## Baseline sequence

1. Confirm the benign canary reaches the expected final context and capture the status, headers, body, length, timing, cache state, and browser result.
2. Add one syntax element at a time and identify the first element that changes edge or application behavior.
3. Send the same semantic value through each legitimate input channel the feature accepts, such as query, path, form body, JSON, multipart field, GraphQL variable, cookie, header, or stored object, while remaining inside scope.
4. Compare raw, URL-encoded, form-encoded, JSON-escaped, HTML-entity, Unicode, and double-encoded representations only when the corresponding layer is known to decode them.
5. Determine whether canonicalization happens before or after validation by tracking the value at every observable stage.
6. Retest the smallest context-correct execution proof in a real browser and retain the negative control.

## Hypothesis families

### Tokenization and grammar

- Test whether the control keys on a literal tag, attribute, event name, scheme, function name, delimiter, or full signature rather than the browser grammar.
- Vary only browser-valid case, ASCII whitespace, comments, separators, quoting, optional delimiters, equivalent property access, or syntactic placement that the observed parser accepts.
- Distinguish HTML tokenization from JavaScript tokenization. A variation valid in one parser may be inert or invalid in the next.
- Do not infer a bypass from a 200 response. Confirm the final DOM, runtime value, event reachability, and execution origin.

### Canonicalization and decoding order

- Test single and repeated URL decoding only when two layers plausibly decode the value.
- Test HTML entities only where an HTML parser resolves them before the security-relevant comparison or sink.
- Test JSON, JavaScript, CSS, and Unicode escapes only where the next parser actually interprets that escape form.
- Compare composed and decomposed Unicode, full-width or compatibility characters, and normalization boundaries only when the application or framework normalizes identifiers or syntax.
- Record malformed-sequence behavior and replacement characters. Never claim a bypass unless the final browser grammar becomes executable.

### Parser differentials

- Compare the server sanitizer's serialized output with the browser's parsed DOM and the live DOM after framework hydration or mutation.
- Check namespace transitions among HTML, SVG, and MathML only when those nodes survive the sanitizer and enter an HTML parser.
- Check nested markup, misnesting, foster parenting, reparsing, and mutation only through `sanitizers-mxss.md`, with exact before/after DOM evidence.
- Check template or markdown renderers as separate parsers; identify which renderer and version converts the attacker value before the native browser sink.

### Alternate delivery channel

- If the edge filters one endpoint or content type, determine whether the same application field is accepted through another documented endpoint, API version, import flow, mobile route, GraphQL mutation, or multipart/JSON representation.
- Treat host, scheme, port, path, query, and fragment as independent URL components. A filter that validates one component does not grant control of another.
- Do not use alternate hosts, redirects, or third-party infrastructure outside program scope. Use d0x-controlled infrastructure and the program's approved targets.

### Stateful and edge behavior

- Compare cache hit and miss, authenticated and unauthenticated, locale, device variant, feature flag, and server region only when the application exposes those states legitimately.
- Separate bot mitigation, rate limiting, and challenge pages from application sanitization by preserving response fingerprints and a benign request sent at the same cadence.
- Stop automated variation when it risks account lockout, service degradation, or policy breach; retain the minimized matched pair for manual validation.

## Context-specific bypass routing

- If the browser receives executable markup after sanitization or reparsing, use `sanitizers-mxss.md`.
- If execution depends on inline handlers, dynamic script loading, `eval`, nonces, hashes, or trusted policies, use `csp-trusted-types.md`.
- If a web-message sender check is the filter, use `postmessage.md`; origin validation is not a string-WAF problem.
- If the issue is a framework template expression or raw-HTML escape hatch, use `dom-xss.md` and identify the compiler, renderer, or native sink.
- If the final render is invisible or delayed, use `blind-and-stored.md` only after the context-correct variant is established.

## Evidence and lead requirements

The lead must contain the exact blocked and bypass requests, raw responses, observed component fingerprints, transformation matrix, final DOM or runtime value, browser/version, execution marker, delivery path, rate/caching controls, and the narrow explanation of why the filter and browser disagree. State whether the root cause is missing context-aware output encoding, premature validation, inconsistent canonicalization, parser differential, unsafe sanitizer configuration, or edge/application route inconsistency.

Do not present a catalog of strings as the finding. The finding is the attacker-controlled source reaching an executable context through a specific, reproducible validation gap.
