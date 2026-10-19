# Sanitizers, Parser Differentials, and Mutation XSS

Use this reference when input is encoded, stripped, sanitized, normalized, converted to DOM, serialized, reparsed, mutated, or processed by more than one HTML/XML/template implementation. The core question is whether the object inspected by the security control is the same object and context later consumed by the browser sink.

## Build the complete parser pipeline

Record each stage explicitly:

```text
attacker bytes
  -> transport/form/URL decoder
  -> server template or serializer
  -> sanitizer and exact configuration
  -> HTML/SVG/MathML/template parser
  -> framework or application post-processing
  -> serialization
  -> second parser or sink
  -> live DOM mutation
```

A sanitization result is not final evidence if application code later concatenates it, changes attributes, moves it into another namespace, extracts text/attributes and reparses them, or passes it through a different document implementation.

## Identify the security control precisely

- Library name, exact version, build, browser/server environment, and DOM implementation.
- Configuration: allowlists, blocklists, profiles, URI rules, custom elements, namespace handling, template mode, XML safety, return type, in-place mode, and hooks.
- Call site and whether the value is modified before or after sanitization.
- Output type: string, DOM node, fragment, document, `TrustedHTML`, or a framework-specific wrapper.
- Whether the same policy is reused across trust boundaries or mutable configuration persists between calls.
- Whether sanitizer output is inserted directly into the final sink or stringified and reparsed.

## Context-preserving probes

Start with inert structure, not immediate JavaScript. Use unique nested elements, attributes, comments, entity-encoded delimiters, SVG/MathML boundaries, template/noscript/style nodes, duplicate ids/names, and serializer-sensitive text. Capture:

1. Input string.
2. Sanitizer output string or DOM.
3. Serialized output after application post-processing.
4. Final live DOM in each relevant browser.
5. Runtime sink values and mutations after load.

The proof target is a structural difference that creates a new executable attribute, element, URL, property path, or gadget only after the security check.

## Mutation XSS

mXSS occurs when a sanitized representation changes during later parsing, serialization, namespace transitions, or DOM mutation. Investigate when the pipeline contains HTML plus SVG/MathML foreign content, comments or text that become markup, nested formatting/table elements, template or noscript handling, DOM serialization followed by `innerHTML`, multiple browser/parser implementations, or rich-text/editor normalization.

Do not paste a historical DOMPurify bypass and assume it applies. Match the exact library/version, configuration, DOM implementation, browser family, and parse/reparse sequence. Use historical vectors only to identify parser behaviors worth testing, then prove the current target's mutation with before/after DOM evidence.

## DOMPurify-specific review

DOMPurify is allowlist- and DOM-based, but unsafe integration can reintroduce XSS. Review outdated versions and advisories, hooks that add or retain unsafe attributes, permissive `ADD_TAGS`/`ADD_ATTR`, URI policy changes, `SAFE_FOR_XML: false` with non-HTML content, custom-element handling, server-side use with an outdated or behaviorally different DOM implementation, mutation after sanitization, and sanitized output passed into a different parser context.

When Trusted Types is used, record whether DOMPurify returns a string or `TrustedHTML`, whether the policy calls it with the expected return mode, and whether a default policy or later stringification weakens the boundary. A Trusted Type documents policy provenance; it does not prove the policy is safe.

## Framework and editor pipelines

Inspect rich-text editors, markdown renderers, email previewers, syntax highlighters, document converters, SVG/icon systems, client template compilers, SSR hydration, and preview-versus-published renderers. Compare storage representation, preview DOM, published DOM, admin/staff DOM, exports, emails, and PDF/headless renderers because they often use different sanitizers or versions.

## DOM clobbering after sanitization

Sanitized HTML may still contain safe-looking `id` and `name` attributes that alter named properties. Route any clobberable property into the exact application gadget and sink; the sanitizer bypass claim is the allowed structure plus unsafe application behavior, not merely the presence of duplicate names.

## Closing criteria

Do not close because one output string looks encoded or because the sanitizer removes an obvious event handler. Close only after the actual final parser pipeline, relevant namespaces, application mutations, configuration, browser behavior, and candidate gadget paths are captured and a discriminating inert probe remains non-executable.

## Evidence checklist

- Exact library/version/environment/configuration/hooks.
- Input, sanitizer output, serialized intermediate, final DOM, and runtime sink value.
- Parser/namespace transitions and browser/version.
- Trusted Types policy and return types when present.
- Minimal structural mutation that enables or refutes execution.
- Positive and negative controls using the same pipeline.
- Code-backed rationale and safe next proof.
