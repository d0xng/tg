# Wordlists — use-case overview

Two sources, in this order of preference:

1. `targets/<program>/wordlists/` — target-derived lists built from the collected
   JS/HTML (recipes A and B in `../SKILL.md`). Highest hit rate, fewest requests.
2. `/opt/wordlists/SecLists/` — generic lists. Real local paths are mapped in
   `WORDLISTS_LOCAL.md`.

Persist every custom list under `targets/<program>/wordlists/` so it is never
rebuilt from scratch.

Useful small SecLists starting points:

- web paths: `/opt/wordlists/SecLists/Discovery/Web-Content/common.txt`
- API paths: `/opt/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt`
- parameter names:
  `/opt/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt`
- vhosts: `/opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`

Start with the smallest relevant list. Large lists require an explicit reason,
program permission for automated scanning, conservative rate limits (`-rate 20
-t 20 -p 0.1-0.5 -se`), and a bounded job timeout (`-maxtime-job`).

Wordlists contain discovery candidates, not exploit payloads. Do not use
credential, SQLi, XSS, command-injection, destructive, or data-harvesting lists
with this skill — ffuf finds the injectable surface, the exploitation skill
proves the injection.
