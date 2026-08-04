| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED pending | DEFECT | low | An unset `IP_TTL` was flattened to 64 before route selection, bypassing a route's IPv4 hoplimit metric. | Linux resolves socket TTL first, then route hoplimit, then the default. Oxide now preserves the unset zero sentinel through socket selection and resolves it after route choice for UDP and raw IPv4. Curated row moves after merge. | B1786-ipv4-route-ttl |
