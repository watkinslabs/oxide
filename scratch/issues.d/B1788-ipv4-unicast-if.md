| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED pending | MISSING | med | `IP_UNICAST_IF` was accepted and read back but did not constrain IPv4 unicast route or source selection. | IPv4 transmit now resolves the stored namespace-local ifindex after `SO_BINDTODEVICE`, then passes the selected interface to the existing route owner. The hosted regression pins namespace lookup and device-binding precedence. Curated row moves after merge. | B1788-ipv4-unicast-if |
