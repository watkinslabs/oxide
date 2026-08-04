# B1760 — resolved startup scope

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 0e423a637 | DEFECT | high | A carrier-present interface that is still administratively down was reported through `RTM_NEWLINK` with `IF_OPER_UP`. Operational state now remains down until both the administrative flag and carrier are up. | Linux's `rtnl_fill_ifinfo` reports down unless the interface is administratively running. A serial x86 probe exposed the divergent startup snapshot; `cargo test -p netlink --lib` passes. | B1760 |
| OPEN | DEFECT | high | `systemd-resolved` retains `Current Scopes: none` after receiving eth0 link and IPv4-address rtnetlink notifications, even though eth0 becomes `UP,LOWER_UP`, has `10.0.2.15/24`, and the resolver displays DNS server `10.0.2.3` and default route yes. | Serial-only x86 traces show resolved subscribed to groups 1/5/9, both the link and address multicast notifications reached its socket, and it returns `io.systemd.Resolve.NoNameServers`; this is not a guest-SSH test or a stalled D-Bus loop. | NEXT |
