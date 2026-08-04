# B1765 — rtnetlink dump-only GET admission

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1765 | COVERAGE | high | Dump-only `RTM_GETADDR`, `RTM_GETNEIGH`, and `RTM_GETRULE` requests had no dispatcher-level test, so a non-dump request could silently become a multipart dump. | `dump_only_get_requests_are_rejected_before_the_dump_builder` drives each type through `NetlinkSocket` and asserts `EOPNOTSUPP`; it passed hosted. | B1765 |
