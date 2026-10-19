# Self-XSS Delivery — prove a path into another controlled viewer

Self-only JavaScript execution is not a reportable XSS finding unless the attacker can cause another user or privileged renderer to process the attacker-controlled value without requiring that victim to paste or author code. Treat the local execution as a primitive and search for the smallest concrete delivery path.

## Establish the primitive

Record the exact source, sink, context, transformations, execution origin, required account state, and every manual action used to trigger it. Identify which step makes the case self-only: local storage, developer console, a same-user profile field, an authenticated request, a fragment that is never shared, or a value the current user alone can write and render.

Do not weaken the claim by hiding victim requirements. If exploitation requires the victim to open developer tools, paste script, disable a browser protection, edit a request, or knowingly author markup, state that and keep the lead as a non-reportable primitive unless a separate flaw removes that requirement.

## Delivery routes to examine

### Shared or cross-user objects

- Determine whether tickets, comments, messages, documents, dashboards, reports, invoices, exports, filenames, profile cards, organization settings, or audit entries written by one controlled account render for a second controlled account.
- Check role-specific renderers such as support, moderator, billing, organization owner, or administrator views using test roles supplied or permitted by the program.
- Prove object ownership and tenant boundaries separately; a cross-user render may also route to `broken-access-control`, `idor-bola`, or `tenant-isolation`.

### Request-forgery-assisted planting

- Determine whether the state-changing request that stores the payload has effective CSRF protection, SameSite constraints, origin checks, reauthentication, and content-type requirements.
- Build a controlled-account delivery harness only when policy permits it. Prove the victim account stores the benign canary before combining it with the execution primitive.
- Keep CSRF and XSS as separate primitives in the lead, including each required precondition and the exact chain between them.

### URL and navigation delivery

- Determine whether a query, path, fragment, OAuth state/return parameter, invitation, share link, deep link, redirect, or preview URL carries the value into the victim's renderer.
- A reflected or DOM path is deliverable only when the attacker can provide a normal URL or request that reaches the sink without asking the victim to modify it.
- For POST-only reflections, examine legitimate auto-submitting form delivery and browser content-type rules with controlled accounts. Do not rely on social engineering beyond opening an ordinary link or page unless the program explicitly accepts it.

### Window and messaging relationships

- Determine whether an attacker-controlled page can open, embed, navigate, or retain a reference to the target window and then supply the value through `postMessage`, `window.name`, opener state, or a documented cross-window flow.
- Use `postmessage.md` for exact sender, origin, schema, and downstream-sink proof. A missing origin check matters only when the attacker can obtain the required window relationship and reach the vulnerable branch.

### Server and asynchronous renderers

- Determine whether a screenshot, PDF, email, notification, import, moderation queue, analytics view, webhook log, or background browser renders the same stored value later.
- Tag each controlled injection point and use `blind-and-stored.md` for delayed observation. Do not seed unrelated production users or operational systems.

### State transfer

- Examine only legitimate application mechanisms that transfer attacker-controlled state between users or sessions, such as share/import, templates, invitations, workspace cloning, public drafts, or organization defaults.
- Cookie, storage, cache, session-fixation, or service-worker delivery requires a separately demonstrated write primitive and controlled-user evidence. Do not assume the attacker can set another origin's state.

## Two-account proof

Use controlled account A as attacker and controlled account B as viewer whenever possible. Capture the plant request from A, the storage or object identifier, the ordinary delivery action, the render request from B, the runtime sink input, and a harmless execution marker in B's origin. Repeat with a benign canary and with a value that should not execute.

If the only plausible viewer is a real employee or third party, stop before sending an execution payload. Use an inert tagged canary when policy allows, record the expected renderer and missing controlled role, and mark validation as blocked by role access rather than collecting third-party data.

## Severity and handoff

Severity follows the victim role, origin authority, persistence, interaction, reach, and demonstrated consequence. A complex controlled delivery chain may still be low severity; a reliable stored render in a privileged origin may be high. Do not label the issue by payload sophistication.

The lead must list every prerequisite, victim action, controlled account and role, plant and render requests, source-to-sink trace, delivery harness, negative controls, execution evidence, policy boundary, and next safe validation step. Hand direct authorization flaws to their owning skills while keeping the XSS delivery chain intact.
