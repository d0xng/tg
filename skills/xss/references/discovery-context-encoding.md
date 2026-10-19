# Discovery, Context, and Encoding

Use this reference for every reflected or stored candidate before choosing a payload. The objective is to identify exactly where attacker-controlled data lands, which characters survive, which transformations occur, and which parser or evaluator consumes the result.

## Start with a unique canary

Use a target- and parameter-specific alphanumeric marker such as `d0xA7b9FieldName`. Keep the first probe free of metacharacters so it survives logs, databases, JSON, templates, proxies, and browsers. Record every occurrence separately; one input may appear in HTML text, an attribute, serialized JSON, an analytics script, and a DOM sink at the same time.

For each occurrence capture five stages whenever they exist:

1. **Original request value:** exact bytes and transfer encoding sent by the tester.
2. **Stored or API value:** exact representation returned by the API or visible in a controlled object.
3. **Raw HTTP response:** response bytes before browser parsing; preserve content type, charset, CSP, Trusted Types directives, and `X-Content-Type-Options`.
4. **Runtime value before the sink:** the value after URL decoding, JSON parsing, entity decoding, framework interpolation, normalization, sanitizer calls, or helper functions.
5. **Parsed live DOM or evaluator input:** the nodes, attributes, property values, script grammar, URL, or code string the browser actually consumes.

Do not use View Source as the only evidence for DOM XSS. JavaScript may create or mutate the vulnerable DOM after the response has loaded.

## Character and transformation matrix

Test characters independently before combining them. A rejection caused by one character must not hide the behavior of the others.

| Probe | What it answers |
| --- | --- |
| `<` and `>` | Whether a new element can be introduced, whether markup is encoded, and whether a later decoder or parser restores it |
| `"` and `'` | Whether a quoted HTML attribute, JavaScript string, JSON string, or template expression can be terminated |
| Backtick | Whether a template literal or tagged-template invocation is reachable |
| `&` | Whether HTML entities are preserved, decoded once, decoded twice, or normalized before sanitization |
| `/` and `\\` | Whether closing tags, paths, escapes, comments, or JavaScript escape sequences can be constructed |
| `=` and whitespace | Whether a new HTML attribute can be formed and which separators the parser accepts |
| `(`, `)`, `;`, comma, colon | Whether executable JavaScript grammar or URL schemes can be completed |
| CR, LF, tab, form feed | Whether filters and parsers disagree about separators or line termination |
| `%`, `+`, `#`, `?` | Whether URL parsing, form decoding, query splitting, fragment handling, or suffix truncation changes the value |

Use a table in the lead with columns: `character`, `request form`, `raw response`, `runtime value`, `live DOM`, and `verdict`. Values should be concrete: `preserved`, `HTML-encoded to &quot;`, `URL-decoded once`, `stripped`, `normalized to /`, `breaks JSON`, or `creates attribute`; never write only “filtered.”

## Decode-count matrix

For the one delimiter that the context requires, compare these forms separately:

- Literal character.
- Percent-encoded byte.
- Double-percent-encoded byte.
- HTML named or numeric entity when the destination is HTML or an attribute.
- JSON Unicode escape when the value crosses JSON.
- JavaScript escape only when the value lands in executable JavaScript grammar.
- Mixed-case or Unicode-normalized spelling only when code proves a normalization stage exists.

The useful question is not “does encoding bypass the filter?” It is “which component decodes which representation, in what order, before which security control and parser?” Persist the observed chain.

## Final-context classification

### HTML text

Determine whether `<` creates an element or becomes text. A literal `<script>` inserted with `innerHTML` does not by itself prove execution because browser behavior differs by insertion method; event-capable elements or another executable sink may still work. Preserve the exact insertion API.

### Quoted or unquoted HTML attribute

Record the element, attribute name, quote type, whether the delimiter survives, whether angle brackets are needed, whether a new attribute can be introduced, and whether the event requires interaction. For URL-valued attributes, analyze the final parsed URL separately from the HTML grammar.

### URL-valued attribute or navigation

Resolve the final URL after entity decoding, URL parsing, base URL resolution, allowlist logic, and browser canonicalization. Record control over scheme, username, password, host, port, path, query, and fragment. A controllable string is not automatically a JavaScript URL sink; prove the navigation or code-loading behavior.

### Inline JavaScript

Record whether input lands in a single-quoted string, double-quoted string, template literal, regular-expression literal, object key/value, expression, statement, JSON blob, or script element boundary. Preserve the following source text because repairing or bypassing it determines whether the entire script parses.

### JSON and serialized application state

JSON is data until another component interprets it. Follow the value through `JSON.parse`, hydration, templating, object assignment, dynamic property lookup, HTML insertion, navigation, or code-loading sinks. Record content type and whether the same bytes are ever served as HTML or JavaScript.

### CSS, SVG, MathML, markdown, and template contexts

Identify the actual parser and version. Determine whether the content is later serialized and reparsed, whether foreign-content namespaces change parsing, whether raw HTML is enabled, and whether a framework template compiler evaluates expressions. Route sanitizer/parser disagreements to `sanitizers-mxss.md`.

## Reflection versus render

- **Reflected server-side:** the attacker value appears in the immediate HTTP response.
- **Stored server-side:** the application persists the value and returns it later.
- **DOM-reflected:** client code reads a current source such as URL or message and inserts it into the DOM without server persistence.
- **Stored DOM:** server or browser storage persists data, and later client code passes it to a sink.
- **Blind:** the attacker cannot directly observe the renderer and requires an attributed delayed signal.

These dimensions may overlap. Name both persistence and execution mechanism in the lead, such as `stored DOM XSS`, `reflected server-side XSS`, or `blind stored XSS in a support console`.

## Controls before payload construction

- Repeat the canary with a benign alphanumeric value to establish the normal render path.
- Remove the candidate delimiter while keeping the rest of the string identical to show which character changes parsing.
- Compare raw response and live DOM to detect browser or framework mutation.
- Disable or bypass only one transformation at a time when using controlled local reproduction.
- Reproduce in the browser family and version relevant to the target; do not promote a parser differential observed only in an unrelated engine.
- Preserve console parse errors, CSP violations, Trusted Types exceptions, sanitizer output, and final node/property values.

## Completion criteria

Discovery is complete only when the lead states the exact source, every observed transformation, final parser/evaluator, complete surrounding context, required delimiter or gadget, controls, delivery path, and the next proof. “The application encodes XSS characters” is not a conclusion.
