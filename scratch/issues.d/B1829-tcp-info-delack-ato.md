# B1829 TCP_INFO delayed-ACK timeout

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | MISSING | low | `TCP_INFO` left `tcpi_ato` zero despite TCP owning the adaptive delayed-ACK interval that governs its ACK timer. | `tcp_info::populate_conn_at` did not project delayed-ACK state; receive arrival spacing and the delayed-ACK timer had no shared interval owner. | B1829-tcp-info-delack-ato01 |
