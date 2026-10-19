# NS-delegation takeover (dangling NS → re-creatable cloud DNS zone) — highest impact

When a subdomain is delegated via **NS records** to a cloud DNS provider but the
hosted zone was deleted, you can re-create the zone on that same provider and get
re-assigned the same nameserver set → **full control of the subdomain's DNS**.
You can then point A/CNAME/MX anywhere, issue valid TLS certs (ACME
HTTP-01/DNS-01 will succeed because you control the zone), and host arbitrary
content on the trusted name. This beats a normal CNAME takeover — it is
zone-level, not resource-level.

## Vulnerable NS patterns

| Provider | Delegated NS pattern |
|---|---|
| AWS Route 53 | `ns-*.awsdns-*.{com,net,org,co.uk}` |
| Google Cloud DNS | `ns-cloud-*.googledomains.com` |
| Azure DNS | `ns*-*.azure-dns.{com,net,org,info}` |
| DigitalOcean DNS | `ns*.digitalocean.com` |
| Vultr DNS | `ns*.vultr.com` |
| Linode DNS | `ns*.linode.com` |

## Detection — confirm the delegation is actually dangling

A delegation is only dangling if the **assigned NS do not serve the zone**.
Prove that before claiming:

**`+short` hides the rcode — never read a dangling-delegation verdict from an empty
`+short`.** Measured: SERVFAIL, REFUSED, NXDOMAIN and "no SOA in the answer" all
print nothing and exit 0, and in this class SERVFAIL (delegation exists, zone
deleted → takeoverable) and NXDOMAIN (the name is simply gone) are **opposite**
verdicts. Use `+short` only to read record values; use `+noall +comments` (or grep
`status:`) on anything whose answer is a status.

```bash
dig +short NS sub.target.com                        # delegated to one of the patterns above? (a value — +short is fine)
dig SOA sub.target.com | grep -E 'status:'          # read the RCODE, not an empty line
# equivalently: dig +noall +comments SOA sub.target.com
# Query the delegated NS DIRECTLY — this is the decisive test (no +short):
dig +noall +comments @ns-1234.awsdns-56.org sub.target.com SOA   # REFUSED / SERVFAIL = the zone is not hosted there
dig +noall +comments @ns-1234.awsdns-56.org sub.target.com ANY   # same signal
```

If the delegated NS answers `REFUSED`/`SERVFAIL` for the zone's SOA, the hosted
zone was deleted → the delegation is dangling and re-creatable. If it answers
`NOERROR` with a real SOA, the zone is live → not takeoverable, drop it. If it
answers `NXDOMAIN`, the name itself is gone — that is not this vector.

## Method — re-roll the nameserver set until it matches

1. In **your own** account on that same provider (e.g. Route 53), create a hosted
   zone named `sub.target.com`.
2. The provider assigns you a nameserver set. If it does **not** overlap the
   target's delegated NS, **delete and re-create** the zone to re-roll. The NS
   pools are limited (Route 53 draws from a finite set of `awsdns` delegation
   sets), so with repeated re-creation you eventually get a set that matches the
   target's existing NS delegation. This is feasible on Route 53 / GCP DNS /
   Azure DNS / DigitalOcean and the others.
3. Once your assigned NS overlap the target's delegated NS, the subdomain's DNS
   now resolves **through your zone** → total control.

## Non-destructive proof

- Prove control with a **benign TXT or A record you set** in your zone and then
  resolve it publicly:
  ```bash
  # after your zone's NS overlap the delegation:
  dig +short TXT sub.target.com    # returns your benign marker, e.g. "sdto-poc-<reportid>"
  dig +short A   sub.target.com    # returns an IP you control serving poc-<reportid>.txt
  ```
- Do **not** set MX/CNAME that intercepts real traffic, do not disrupt the
  target's other records, and remove your zone after capturing the PoC.
- The re-runnable evidence is: the dangling-NS `dig @delegated-ns … SOA` =
  SERVFAIL output, the provider zone-creation showing the overlapping NS set, and
  the public resolution of your benign TXT/A on the trusted name.

## SPF `include:` / MX takeover → email spoofing

A cousin vector that pays as Medium (higher if it enables password-reset /
magic-link interception):

```bash
dig +short TXT target.com | grep -i spf     # e.g. "v=spf1 include:mail.vendor.com -all"
dig +short A   mail.vendor.com              # is the included host itself takeoverable?
dig +short MX  target.com                   # MX → a takeoverable mail host?
```

- If an SPF `include:` (or an MX target) points at a **takeoverable** host, take
  it over per the catalog, then send mail that **passes SPF** (and often DKIM if
  the delegated host signs) as `@target.com` → high-credibility phishing on the
  trusted domain.
- Prove it by sending **one** SPF/DKIM-authenticated test mail to **your own**
  inbox and showing the `Authentication-Results:` header PASS. Never send to real
  users.
- Escalate the framing if the target emails **password-reset / magic-link /
  email-verification** tokens — spoofed mail from a trusted, SPF-passing
  `@target.com` sender is a materially stronger phishing → ATO chain than a
  look-alike domain.
