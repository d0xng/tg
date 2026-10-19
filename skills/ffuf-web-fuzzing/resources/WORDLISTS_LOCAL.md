# Local Wordlists

This host has SecLists installed at:

```text
/opt/wordlists/SecLists
```

Use these real paths for ffuf tasks:

## Quick / Safe

```text
/opt/wordlists/SecLists/Discovery/Web-Content/common.txt
/opt/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt
/opt/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
/opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

## Medium

```text
/opt/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
/opt/wordlists/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt
/opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
```

## Large / Requires Care

```text
/opt/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
/opt/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt
/opt/wordlists/SecLists/Discovery/Web-Content/raft-large-words.txt
/opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
/opt/wordlists/SecLists/Discovery/DNS/namelist.txt
```

## Backup / Config

```text
/opt/wordlists/SecLists/Discovery/Web-Content/Common-DB-Backups.txt
```

Prefer Quick/Safe lists first. Use Medium/Large lists only when the task has a
clear target, rate limit, timeout, and stop condition.
