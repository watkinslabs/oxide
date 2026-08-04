| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED pending | DEFECT | low | An AF_INET6 raw socket reached the SOL_IP tables, so `IP_ROUTER_ALERT` could set IPv4 option state without an IPv4 Router Alert chain slot. | Linux `net/ipv6/ipv6_sockglue.c::ipv6_{set,get}sockopt` delegates SOL_IP only when `sk_type != SOCK_RAW`; raw IPv6 receives `ENOPROTOOPT`. Both Oxide raw option dispatchers now reject the entire SOL_IP level for `Raw6`; `cargo check -p syscalls`. Curated row moves after merge. | B1780-raw6-router-alert |
