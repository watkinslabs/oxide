| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 0f65bea7c | DEFECT | med | `IPV6_JOIN_ANYCAST` / `IPV6_LEAVE_ANYCAST` used the multicast membership helper and had no separate anycast socket or device ownership. | Separate per-socket membership list, per-device refcounted ownership, local delivery/NDP ownership, close cleanup, correct acquisition-only CAP_NET_ADMIN check; `cargo test -p net anycast`. Curated rows to move after merge. | B1776-ipv6-anycast-membership |
