# DOM and Client-Side XSS

Use this reference when the browser reads attacker-controlled data and passes it through JavaScript or framework code into an HTML parser, JavaScript evaluator, navigation/code-loading API, template compiler, DOM-clobbering gadget, or prototype-pollution gadget. JavaScript content review remains Read-only under root `AGENTS.md`.

## The required trace

Every lead must show this full chain:

```text
attacker-controlled source
  -> parsing/decoding/normalization
  -> assignments and cross-file callers
  -> validation/sanitization/Trusted Types policy
  -> framework/helper/gadget
  -> final native sink
  -> execution context and delivery
```

Do not promote a sink name without a controllable source, and do not close a source because its first use is safe. Follow aliases, object properties, stores, callbacks, promises, events, API responses, hydration data, and second-order fetches until the value reaches a terminal sink or a demonstrated safe boundary.

## High-value sources

- `location.href`, `location.search`, `location.hash`, path segments, `document.URL`, `document.documentURI`, and `document.baseURI`.
- `document.referrer`, `window.name`, opener/parent/frame state, `history.state`, navigation state, and router parameters.
- `postMessage`, `MessageChannel`, `BroadcastChannel`, service-worker messages, WebSocket/SSE messages, and extension bridges.
- `localStorage`, `sessionStorage`, IndexedDB, cookies readable by script, caches, and persisted client state.
- API, GraphQL, JSON, feature/config endpoints, user profile or content objects, and values returned by attacker-controlled URLs.
- Clipboard, drag/drop, file names and metadata, form values, dataset/attributes, and DOM nodes populated by another parser.
- Query/hash/JSON parsers and recursive merge functions that permit prototype pollution.

## Sink groups

### HTML and document parsing

Review `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`/`writeln`, `Range.createContextualFragment`, `DOMParser.parseFromString`, `srcdoc`, `ShadowRoot.innerHTML`, `setHTMLUnsafe`, framework raw-HTML directives, jQuery HTML constructors/manipulators, and template renderers. Record the exact final native sink rather than only the framework wrapper.

`innerHTML` is an injection sink when it receives an attacker-controlled string. A literal `<script>` assigned through `innerHTML` may not execute, but event handlers and other executable markup can; test the browser's actual parse result. A safe `textContent`, `innerText`, `createTextNode`, or explicit property assignment is evidence of a boundary only if no later code reparses that text as markup.

### JavaScript evaluation

Review `eval`, indirect eval, `Function`/`AsyncFunction` constructors, string arguments to timers, script text setters, event-handler string attributes, framework expression compilers, unsafe template compilation, and libraries that convert strings into functions. Preserve CSP evaluator violations separately from the taint path.

### Code and resource URL loading

Review `script.src`, dynamic `import()`, `importScripts`, worker/shared-worker/service-worker script URLs, module loaders, JSONP callbacks, iframe `srcdoc`, object/embed sources, and trusted loader helpers. Resolve the final URL after base URL resolution, decoding, allowlist logic, suffix/prefix concatenation, and fragments. For cross-origin modules, record CORS and CSP requirements; a controlled authority is strongest when the attack server returns the required module response headers.

### Navigation and scriptable URL sinks

Review `location`, `location.href`, `location.assign`, `location.replace`, `window.open`, link/form actions, router redirects, and custom URL handlers. Determine whether the attacker controls a JavaScript-capable scheme or only an ordinary off-origin navigation, and whether a user gesture or sandbox changes behavior.

### Framework and library sinks

- React: `dangerouslySetInnerHTML`, raw ref assignments, portals, hydration data, and third-party renderers.
- Vue: `v-html`, render functions, runtime template compilation, and unsafe directives/plugins.
- Angular/AngularJS: `[innerHTML]`, bypass-security-trust APIs, legacy expression compilation, and version-specific sandbox/CSP behavior.
- Svelte: `{@html}` and actions/components that write native DOM properties.
- jQuery: `$()` with attacker HTML, `.html()`, `.append()`, `.after()`, `.replaceWith()`, `parseHTML`, selector/history edge cases, and plugin-specific template sinks.
- Markdown/rich-text/editor libraries: raw HTML mode, custom renderers, URL sanitization, plugin hooks, preview-versus-published differences, and serialize/reparse behavior.

## Runtime confirmation without content search

Use a unique canary in one source at a time. In a controlled browser, inspect the runtime value at the sink, stack/caller path, final DOM/property, and console violations. Source review of JS files must be performed through Read only; browser debugger and runtime instrumentation may confirm the already identified path but must not substitute for full JavaScript coverage.

## DOM clobbering

DOM clobbering needs three concrete pieces: an HTML injection, a clobberable property path, and a gadget that sends the clobbered value to a dangerous sink. Inspect implicit named properties on `window`, `document`, forms, collections, elements with duplicate `id`/`name`, and code patterns such as `window.config || default`, `document.someName`, or unchecked property chains. Prove the clobbered runtime type and value immediately before the sink. Pay special attention to gadgets feeding `script.src`, dynamic imports, iframe/worker URLs, service-worker registration, event handlers, or HTML parsing.

## Prototype pollution to XSS

Treat client-side prototype pollution as a source plus gadget problem. Identify a pollution source in query/hash parsing, JSON/message handling, or unsafe recursive merge; verify a harmless unique property in a controlled page; find an inherited property consumed by a sink; then combine them with the smallest non-destructive execution marker. Test `__proto__`, `constructor.prototype`, nested key parsing, recursive sanitization, and undefined option properties only when code or runtime behavior supports them. Clean up or reload into a fresh context after each controlled test.

## Trusted Types review

Trusted Types enforcement blocks strings at covered sinks, but a lead may remain exploitable through an unsafe default policy, an overly broad `createHTML`/`createScript`/`createScriptURL` policy, a policy that returns input unchanged, a sanitizer configured unsafely, a sink outside enforcement, or code that stringifies trusted values and reparses them elsewhere. Record the exact policy creation and the type/value immediately before the sink.

## Lead evidence

- Exact source and attacker control.
- Every decode, assignment, helper, guard, sanitizer, policy, and caller.
- Exact native sink and runtime value.
- File, line, module, component, and route.
- Final context and character matrix.
- Controlled browser reproduction and delivery mechanism.
- Positive and negative controls.
- CSP/Trusted Types console evidence.
- Gadget prerequisites for clobbering or pollution.
- Impact achievable in a controlled second-user or privileged test context.
