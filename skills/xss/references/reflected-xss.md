# Reflected XSS

Use this reference when attacker-controlled data returns in the immediate response or is immediately rendered by a client route without persistence. Read `discovery-context-encoding.md` first.

## Workflow

1. Identify every input carrier: query parameter, path segment, fragment passed to the server, form body, JSON body, GraphQL variable or operation name, cookie, request header, error message, redirect parameter, localization value, or upstream metadata.
2. Place a unique canary and map every raw-response and live-DOM occurrence independently.
3. Build the character and decode-count matrix for the exact context.
4. Determine whether the server reflection executes directly, whether client JavaScript performs a second unsafe insertion, or whether both stages contribute.
5. Construct the minimum context-correct local execution proof without an external callback.
6. Prove deliverability: an exact URL, controlled link, controlled auto-submitting form, controlled iframe/opener harness, or another request a victim can realistically trigger without possessing the attacker's session secrets.
7. Record interaction requirements, origin, authentication state, affected role, CSP/Trusted Types behavior, and the negative control.

## Context rules

- **Between tags:** determine which elements and events survive the application and browser parser. Do not assume `<script>` is the only or best execution path.
- **Inside an attribute:** test the matching quote first. If angle brackets are encoded, determine whether a new event or URL-valued attribute can be introduced without creating a new element.
- **Inside a URL attribute or redirect:** inspect scheme and authority validation, final canonical URL, navigation method, user-gesture requirement, and whether a `javascript:` or attacker-controlled script URL is actually executed by that sink.
- **Inside JavaScript:** preserve syntactic validity. Identify the string/expression/template context, escaping routine, following grammar, script-element boundary, and whether HTML parsing occurs before JavaScript parsing.
- **Inside JSON:** follow the consumer. A reflected string in valid JSON is not XSS until another parser or sink interprets it as HTML, JavaScript, a template, or a code/resource URL.
- **Inside CSS, SVG, MathML, markdown, or a client template:** identify the actual parser, namespace, framework/version, sanitizer, and later serialization/reparse stages.

## Delivery and self-context traps

A payload firing only after manually editing DevTools, changing local storage, or altering a request that a victim cannot be induced to send is not a delivered reflected XSS. Document the realistic carrier and the minimum victim action. For POST-only reflections, determine whether a controlled cross-origin form can reproduce the request under SameSite, CSRF, content-type, and framing constraints. For authentication-bound parameters, determine whether the URL or request works in the controlled victim account rather than only in the attacker's session.

Do not use a blind collector as the first proof when the response is visible. An OOB failure may mean CSP or egress blocked the callback rather than execution. First prove code execution and origin locally; use OOB only for a genuinely invisible downstream renderer.

## Sibling sweep

When one reflection is exploitable, inspect every parameter and route using the same response template, error handler, localization helper, redirect helper, serializer, or JavaScript bootstrap object. Keep one precise lead per root cause or independently reportable surface and deduplicate by `primitive|host|claim`.

## Evidence checklist

- Exact request and victim-deliverable construction.
- Raw response excerpt plus live DOM or runtime sink evidence.
- Character/transformation matrix and final context.
- Context-specific payload rationale and exact execution origin.
- Required user interaction and authentication state.
- Enforced CSP and Trusted Types behavior.
- Positive, character, delivery, and negative controls.
- Code location when JavaScript or a template helper completes the exploit.
- Concrete impact reachable in a controlled victim account; severity remains a validation decision.
