# postMessage and Cross-Window XSS

Use this reference when attacker-controlled data enters or leaves a window through `postMessage`, a `message` event, `MessageChannel`, `BroadcastChannel`, popup/opener communication, iframe bridges, embedded widgets, extension bridges, or service-worker messaging.

## Model both sides of the channel

Record the sender, receiver, expected origin, window relationship, message schema, validation, downstream actions, and reply behavior. Review both directions: an unsafe receiver may turn `event.data` into XSS, while an unsafe sender may disclose tokens or sensitive state to an attacker-controlled receiver because it uses `targetOrigin: "*"` or posts to a navigable window.

## Receiver workflow

1. Locate each `message` listener and identify how it is registered and removed.
2. Record every access to `event.origin`, `event.source`, `event.data`, `event.ports`, and message type/discriminator fields.
3. Reconstruct the exact accepted message schema, including nested objects, JSON parsing, type coercion, default values, merge operations, and prototype-sensitive keys.
4. Trace every accepted field into HTML, URL, navigation, storage, request, code-loading, template, or direct-evaluation sinks.
5. Determine how an attacker obtains a reference to the target window: iframe, popup, opener, parent, sibling frame, embedded widget, or a window previously opened by the target.
6. Build a controlled sender harness and test a harmless canary first.

## Sender validation rules

A robust receiver compares `event.origin` to an exact expected origin including scheme, host, and port, and checks `event.source` when the expected window is known. It validates the structure and types of `event.data` after sender identity is established.

Treat these patterns as candidate weaknesses requiring proof:

- No `origin` check.
- `indexOf`, `includes`, `startsWith`, or `endsWith` substring checks that permit attacker registrable domains, prefixes, suffixes, alternate schemes, or ports.
- Regular expressions without complete anchoring or with unescaped dots and permissive wildcards.
- Comparing only hostname while ignoring scheme or port when those distinctions matter.
- Trusting a message solely because it has a recognized `type`, action, nonce copied from public page data, or JSON shape.
- Checking `origin` but not `source` when any attacker-controlled window on the allowed origin can send the message.
- Checking `source` but allowing that window to navigate to an attacker origin before the relevant operation.
- Treating `document.domain` as equivalent to `event.origin`; message origins are not relaxed by `document.domain`.
- Mishandling IDN Unicode and punycode forms in custom string comparisons.
- Accepting opaque or `null` origins without a narrowly justified sandbox/file/data workflow.

## Controlled sender harnesses

Use only controlled origins and accounts. Prefer the exact relationship the real application supports.

```html
<iframe id="target" src="https://target.example/path"></iframe>
<script>
  const frame = document.getElementById("target");
  frame.addEventListener("load", () => {
    frame.contentWindow.postMessage(
      { type: "candidate-action", value: "d0x-canary" },
      "https://target.example",
    );
  });
</script>
```

For popup flows, record the user gesture requirement, opener behavior, COOP isolation, popup redirects, and the precise moment the target window accepts the message. Use an exact `targetOrigin` in the harness unless testing a sender-side wildcard defect.

## High-value downstream sinks

- HTML parsing: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `srcdoc`, `document.write`, framework raw-HTML helpers, and markdown/template renderers.
- JavaScript evaluation: `eval`, `Function`, string timers, event-handler strings, expression compilers, and script text.
- Code/resource loading: script, dynamic import, worker/service-worker, iframe, object/embed, and module-loader URLs.
- Navigation and OAuth/session flows: `location`, popup redirect, callback URL, token response, account linking, and logout/login messages.
- Prototype pollution: parsing or merging attacker message objects into application configuration, then reaching an inherited gadget.
- Privileged actions: API requests, storage writes, clipboard access, extension/native bridges, payment actions, or tenant/object selections triggered by a message.

## Sender-side disclosure

Review every outbound `postMessage`. An exact receiver origin should be supplied whenever the receiver is not an opaque origin. If the target posts secrets with `"*"`, determine whether an attacker can control or navigate the receiving window and read the message. Record window lifecycle and navigation races; a reference to the same `Window` object may survive navigation while its origin changes.

## Controls and evidence

- Positive control from the legitimate sender with the expected schema.
- Negative control from an unrelated origin.
- Bypass candidate that differs only in the flawed origin-check property.
- `event.origin`, `event.source`, target window relationship, and exact message object.
- Runtime value at the downstream sink and complete source-to-sink trace.
- Framing/popup constraints: CSP `frame-ancestors`, X-Frame-Options, sandbox, COOP/COEP, user gesture, and authentication state.
- Controlled victim delivery and exact impact; a weak check with no reachable security-sensitive sink remains a lead, not a finding.
