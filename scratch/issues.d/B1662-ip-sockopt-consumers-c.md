# B1662-ip-sockopt-consumers-c

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | med | No IPv6 packet forwarding at all: there is no `forward_ipv6_in` and nothing routes a non-local IPv6 destination onward. `IPV6_ROUTER_ALERT` therefore has no delivery point — this branch gives it real chain-slot state and the correct selector semantics, but the fan-out its IPv4 twin got has nowhere to hang until an IPv6 forwarding path exists. | `grep -rn "forward_ipv6\|forward6" crates/kernel/net/src` finds nothing; the IPv4 twin lives in `stack_forward::forward_ipv4_in`. | — |
| OPEN | low | `IP_ROUTER_ALERT` set on a raw **IPv6** socket stores the option bit but takes no chain slot: the chain holds `Raw4Endpoint`s, since delivery hands the copy to the IPv4 raw receive queue. The reference does not screen the family here. | `054_setsockopt/ip.rs` `Action::RouterAlert` matches `SockKind::Raw4` only. | — |
| OPEN | med | `IPV6_JOIN_ANYCAST` / `IPV6_LEAVE_ANYCAST` still route to the multicast helper — no anycast address state, no per-device anycast list, no capability screen of their own. Untouched by this branch. | `054_setsockopt/ipv6.rs` sends both to `ipv6_mcast_membership`. Part of the curated IP-sockopt-consumers row. | — |
