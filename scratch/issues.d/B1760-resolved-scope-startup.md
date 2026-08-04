# B1760 — resolved startup scope

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 0e423a637 | DEFECT | high | A carrier-present interface that is still administratively down was reported through `RTM_NEWLINK` with `IF_OPER_UP`. Operational state now remains down until both the administrative flag and carrier are up. | Linux's `rtnl_fill_ifinfo` reports down unless the interface is administratively running. A serial x86 probe exposed the divergent startup snapshot; `cargo test -p netlink --lib` passes. | B1760 |
