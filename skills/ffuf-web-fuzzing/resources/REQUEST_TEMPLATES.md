# Raw request templates (`ffuf -request`)

Raw-request mode is the right tool for any authentication ffuf cannot express as
flags: JWT, session cookie + CSRF token, API key headers, Basic, OAuth2 bearer,
JSON bodies, GraphQL.

How ffuf reads these files: the **request line path + the `Host:` header** build
the URL, and `-request-proto https` supplies the scheme. There is no separate
URL flag in this mode.

```bash
ffuf -request targets/<program>/req.txt -request-proto https \
  -w targets/<program>/wordlists/small.txt \
  -mc 200,400,401,403,404 -fw 190 \
  -rate 5 -t 5 -p 0.2-0.5 -se \
  -o targets/<program>/notes/ffuf-raw-request.json -of json
```

Rules that apply to every template below:

- Export the request from the authorized browser/proxy session, store it under
  `targets/<program>/` (raw copies and any response bodies under
  `targets/<program>/notes/`), and redact tokens in anything that becomes a lead
  or a report.
- Replace **exactly one** benign value with `FUZZ`.
- Use only your own test accounts and objects you own.
- Generate id ranges with `python3 ../ffuf_helper.py wordlist -o ids.txt -t numbers -s <start> -e <end>`;
  scaffold a new template with `python3 ../ffuf_helper.py create-req -o req.txt -m POST -u https://api.<host>/path -H 'Authorization: Bearer <token>' -d '{"q":"FUZZ"}'`.

## Path value (JWT bearer)

```http
GET /api/v1/orders/FUZZ HTTP/1.1
Host: api.<host>
Authorization: Bearer <your-own-jwt>
Accept: application/json
Connection: close
```

## Session cookie + CSRF token

```http
POST /api/v1/settings/FUZZ HTTP/1.1
Host: app.<host>
Cookie: session=<your-own-session>; csrftoken=<token>
X-CSRF-Token: <token>
Content-Type: application/x-www-form-urlencoded
Connection: close

value=1
```

## API key header

```http
GET /v2/reports/FUZZ HTTP/1.1
Host: api.<host>
X-Api-Key: <your-own-key>
Accept: application/json
Connection: close
```

## HTTP Basic

```http
GET /internal/FUZZ HTTP/1.1
Host: <host>
Authorization: Basic <base64 user:pass for your own account>
Connection: close
```

## OAuth2 bearer with a tenant/org header

```http
GET /api/v1/projects/FUZZ HTTP/1.1
Host: api.<host>
Authorization: Bearer <your-own-access-token>
X-Org-Id: <your-own-org-uuid>
Accept: application/json
Connection: close
```

Only the id in the path carries `FUZZ` here. Swapping the **org header** is a
tenant-isolation test, not a discovery job — that belongs to `tenant-isolation`.

## JSON property name

```http
POST /api/v1/search HTTP/1.1
Host: api.<host>
Authorization: Bearer <your-own-token>
Content-Type: application/json
Connection: close

{"FUZZ":"1"}
```

Property-name fuzzing surfaces undocumented and mass-assignable fields. A field
that changes the response is a lead for `idor-bola` (mass assignment), not a
finding on its own.

## JSON property value

```http
POST /api/v1/orders/preview HTTP/1.1
Host: api.<host>
Authorization: Bearer <your-own-token>
Content-Type: application/json
Connection: close

{"order_id":"FUZZ"}
```

## GraphQL field / operation probing

```http
POST /graphql HTTP/1.1
Host: api.<host>
Authorization: Bearer <your-own-token>
Content-Type: application/json
Connection: close

{"query":"query { FUZZ { id } }"}
```

Use a field-name wordlist and filter on the `Cannot query field "x"` error size —
the entries that do **not** produce that error exist. When introspection is
enabled, read the schema instead; alias-batching and introspection are owned by
`broken-access-control` (`../../broken-access-control/references/graphql-api.md`).

Check that the request's `Host` header names an authorized target before running.
Never put live tokens in leads, reports, or Git.
