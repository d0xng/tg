# Seeing the schema — including when they turned introspection off

Without the schema you are guessing field names. With it you have the equivalent of
a Swagger file: every operation, every argument, every type, and the arguments'
types. **Introspection being disabled does not end this** — it is the normal
production case, and everything after the first section exists for it.

## Contents

- Introspection, and the query actually worth sending
- When `__schema` is blocked: the `__type` canary
- Field suggestions — the schema leaks through typos
- Field stuffing and type stuffing
- Automating recovery, and why the wordlist is the whole game
- The non-production sibling
- Errors, debug mode and stack traces
- What to do with the schema once you have it

## Introspection, and the query actually worth sending

The seven introspection meta-types are `__Schema`, `__Type`, `__TypeKind`,
`__Field`, `__InputValue`, `__EnumValue`, `__Directive`. The one-liner everyone
sends returns type *names* only, which is nearly useless:

```graphql
{ __schema { types { name } } }        # names, no operations, no arguments
```

Send this instead — entry points, and the arguments that are your injection
surface:

```graphql
query {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types { kind name fields { name args { name type { name kind ofType { name } } } } }
    directives { name args { name } locations }
  }
}
```

Read it for four things, in this order: **mutations** (state change), **queries
that reach identity**, **arguments whose names look like URLs, filters or
commands**, and **`subscriptionType` non-null** (which means WebSocket, see
`injection-forgery.md` §CSWSH). The `directives` block is how you learn the
authorization model exists at all (`authz-paths.md`).

A response of ~2,000 lines is normal. `InQL` renders it to TSV/HTML and `GraphQL
Voyager` draws it — in Voyager, the **arrows that form a cycle** (`Paste.owner →
Owner.pastes → …`) are the circular relationships that make the DoS families
possible, which you recognize and do not fire.

## When `__schema` is blocked: the `__type` canary

Filters and WAF rules are commonly written against the string `__schema` and
nothing else — a real AWS AppSync WAF rule matched `Body CONTAINS "__schema"` and
let every other meta-field through. So a rejected introspection query does **not**
mean introspection is disabled. Send the canary:

```graphql
{ __type(name: "Query") { name } }
```

Its answer is predetermined — the root query type is named `Query` — so:

```json
{"data":{"__type":{"name":"Query"}}}     <- introspection is NOT actually disabled
```

Anything else (an `errors` block naming introspection, a `400`) means the block is
real. When the canary answers, you have full introspection one type at a time:

```graphql
{ __type(name: "User") { name kind fields { name type { name kind } } } }
```

Note what the response tells you even when the type does **not** exist: a null
`__type` versus a populated one is a clean existence oracle over type names, which
is what type stuffing below rides on.

## Field suggestions — the schema leaks through typos

Most implementations answer a misspelled field with the correction:

```json
"message": "Cannot query field \"titlr\" on type \"PasteObject\". Did you mean \"title\"?"
```

**`Did you mean` in any error means the schema is recoverable**, independently of
introspection. Three properties make it an extraction primitive rather than a
curiosity:

- **the edit-distance threshold is computed, not fixed.** The reference
  implementation uses `floor(len(input) * 0.4) + 1`, so a 7-character field is
  reachable from a typo 3 edits away. Short probes match little; probes near the
  target's length match a lot.
- **one typo can return several fields** — `owne` yields *"Did you mean `owner` or
  `ownerId`?"*. Each error line is multiple names.
- **there is no limit on typos per document.** Every bad field produces its own
  error entry, so one request harvests many:

```graphql
query { pastes { tte  tent  bli  urn } }
```

Combine with aliases (`batching-abuse.md`) to raise the yield per request further.
The correction only fires for *fields, arguments and types* — a typo in the root
operation keyword is a syntax error, not a suggestion.

Field suggestions are being tied to the introspection setting upstream, so on
patched, current servers this dies with introspection. Assume it works, verify from
the response, and do not report "field suggestions are enabled" as a finding —
report what you recovered with it.

## Field stuffing and type stuffing

When suggestions are off too, guess. **Field stuffing** takes a query you already
know works and adds candidate fields to its selection set — GraphQL object fields
usually map close to database columns:

```graphql
query { user { name  username  email  emailAddress  phone  mobile
               password  passwordHash  apiKey  token  accessToken
               ssn  birthday  address  isAdmin  role  status } }
```

Valid names resolve and return data; invalid ones error individually, so a single
request tells you which of twenty guesses exist. **Watch the case convention**: SDL
files are commonly written `api_key` while the wire format is `apiKey`, because
some implementations convert automatically. Try both — a miss on one is not a miss.

**Type stuffing** is the same move through the `__type` canary, guessing type names
rather than field names. Type names are conventionally `UpperCamelCase`
(`PasteObject`, `UserAccount`, `PrivateProfile`).

## Automating recovery, and why the wordlist is the whole game

`Clairvoyance` stitches suggestions and stuffing into a reconstructed schema from a
wordlist, and against a suggestion-enabled server it recovers most of the schema.
Its quality is entirely the wordlist's:

- password and directory wordlists are the wrong shape — you want **English
  dictionary words**, because field names are words;
- **build a target-specific list from the target itself**: scrape the app's own
  frontend for nouns (`cewl <url>`), and add every identifier you already pulled
  out of the JS bundles (`../../js-source-to-sink` gives you these for free —
  operation names, variable names and field names appear verbatim in the client);
- for a non-English application, use that language's dictionary.

The bundle-derived list is the one that outperforms, and you usually already have
it before you reach this file.

## The non-production sibling

Before grinding a recovery, spend one request per candidate host: staging and dev
deployments of the same API very often keep introspection, debug mode and the IDE
enabled, and their schema is the production schema. `dev.`, `staging.`, `stage.`,
`test.`, `uat.`, `qa.`, `preprod.`, `internal.` prefixes on the API host, and the
same `/graphql` path list from `recon-fingerprint.md`. Recover there, attack
production with what you learned — and note that reaching the *data* on a staging
host is a different, usually weaker, finding than reaching it on production.

## Errors, debug mode and stack traces

The GraphQL error object is `message`, `locations`, `path`, `extensions`. Almost
all disclosure is in **`message`**; `extensions` is where implementations put error
codes, timings and — when debug is on — stack traces.

Provoke errors deliberately: malformed documents, special characters where a value
is expected, a required argument omitted, wrong scalar types, and unusual HTTP
methods (`PUT`, `PATCH`) against the endpoint. What comes back is frequently more
than an error:

```json
"message": "(sqlite3.IntegrityError) UNIQUE constraint failed: users.username
            [SQL: INSERT INTO users (username, password) VALUES (?, ?)]
            [parameters: ('tom', 'secret')]"
```

That one line names the engine, the table, two columns, the statement shape — and
shows the password stored in the clear. It is simultaneously an information
disclosure, a SQLi roadmap (`../../sqli`) and an account-existence oracle.

**Debug mode is sometimes client-togglable**: `?debug=1`, Magento's documented
`?XDEBUG_SESSION_START=PHPSTORM`, or a cookie. And remember the endpoint
differential from `recon-fingerprint.md` — stack traces suppressed on `/graphql`
are often live on `/graphiql`.

A stack trace hands you absolute filesystem paths, the OS account, framework and
dependency versions, and source fragments. Keep it in `notes/`, route versions to
`../../infra-panels-default-creds` and any credential to `../../exposed-secrets`.
**Verbose errors alone are auto-discarded** — they are a lead, not a report.

## What to do with the schema once you have it

Recovering the schema is still rung 0. Immediately convert it into a target list:

1. every **mutation** — what state does it change, and for whom;
2. every path to a **type that holds identity or PII** → `authz-paths.md`;
3. every argument named like a **URL, a filter, a path, or a command** →
   `injection-forgery.md`;
4. every **id-shaped argument** → `batching-abuse.md` to sweep it, `../../idor-bola`
   to grade it;
5. `subscriptionType` → `injection-forgery.md` §CSWSH.

## Source

Distilled from *Black Hat GraphQL* (Aleks & Farhi, No Starch Press, 2023),
chapter 6, with the introspection mechanics from chapters 3–4. `InQL`,
`Clairvoyance`, `GraphQL Voyager`, `cewl` and `graphql-path-enum` are that book's
toolchain — confirm availability in `../../_shared/references/tooling.md`; every
technique above is reproducible with `curl` alone.
