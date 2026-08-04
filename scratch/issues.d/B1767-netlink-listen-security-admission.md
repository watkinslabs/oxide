# B1767 — netlink listen admission

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1767 | DEFECT | low | AF_NETLINK `listen(2)` skipped network-security admission before reporting its unsupported-operation errno. | `listen_admits_before_its_unsupported_operation_errno` proves the owner returns `EOPNOTSUPP` normally and `EACCES` under a denial. | B1767 |
