# F808 — TCP_INFO receive counter group

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 8aa351a4c | DEFECT | low | `TCP_INFO` now reports connection-owned receive segment count, received bytes, out-of-order packet count, and bytes accepted but not yet emitted. | `tcp_info::tests::populate_reads_the_connection_owned_receive_and_send_counters`; `tcp_conn` tests cover receive, out-of-order promotion, and the canonical send queue. | FIX02-F808-tcp-info-recv-counters |
