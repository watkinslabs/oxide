# F809 — TCP_INFO transmit counter group

Fixed on `fix/f809-tcp-info-tx-counters`.

| Status | Type | Severity | Issue | Evidence | Claim |
|---|---|---|---|---|---|
| FIXED (pending merge) | DEFECT | low | `TCP_INFO` did not report connection-owned transmit progress: `tcpi_bytes_acked`, `tcpi_segs_out`, `tcpi_data_segs_out`, `tcpi_bytes_sent`, or `tcpi_bytes_retrans`. | Canonical ACK, transmit, and retransmit paths now own the counters; focused tests plus the full net suite, lint, x86/ARM feature gates, and x86/ARM smoke boots pass. | FIX03-F809-tcp-info-tx-counters |
