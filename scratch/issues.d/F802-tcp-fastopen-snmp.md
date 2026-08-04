# F802 — TCP Fast Open extended counters

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED (this PR) | DEFECT | low | **The Fast Open counters were absent from the TCP extended statistics.** TCPFastOpenPassive, TCPFastOpenPassiveFail, TCPFastOpenPassiveAltKey, TCPFastOpenCookieReqd, and TCPFastOpenListenOverflow now arise from the passive Fast Open decision that owns their semantics, then feed the per-network-namespace MIB owner and its live /proc/net/netstat projection. | tcp_fastopen/server_tests.rs::the_decision_names_each_tcp_ext_event_at_the_rung_that_caused_it; mib::render_tests::tcp_fast_open_events_render_in_their_tcp_ext_columns; focused net and procfs suites. | F802 |
