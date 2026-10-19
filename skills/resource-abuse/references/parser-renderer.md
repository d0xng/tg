# Parser And Renderer Checks

Use when an endpoint stores or renders markdown, rich text, diagrams, mentions,
links, embeds, templates, Mermaid, or sanitized HTML.

## Safety

- Use a single small synthetic object first.
- Do not use known parser bombs, recursive expansion payloads, regex
  backtracking payloads, compression bombs, malicious embeds, or inputs intended
  to exhaust memory/CPU or crash clients.
- Prefer preview/render endpoints over persisted shared views.

Bounds: `../../_shared/references/safe-ladder.md` rung 2b (2–3 invocations, own
account, stop on the first sign of shared pressure) plus §B's Step-0 policy gate
in `../SKILL.md`. Do not restate them here.

## Method

1. Create one owned synthetic object with normal rich text and record baseline
   response time, render time if observable, status, and cleanup path.
2. Submit at most one or two small complexity variants using normal product
   syntax: many links, many mentions to owned/test users, repeated markdown
   constructs, simple tables, long but valid URLs, or repeated safe formatting.
3. Compare response/render timing and server behavior with baseline.
4. Capture whether link unfurling, embed processing, diagram rendering, or
   sanitization runs repeatedly.
5. Stop immediately on the first strong signal.

## Good Evidence

- small valid rich-text input causes disproportionate server render time;
- preview and persisted render both lack complexity limits;
- server performs expensive link unfurling or embed processing repeatedly;
- saved content makes an owned page unreliable without high request volume.
