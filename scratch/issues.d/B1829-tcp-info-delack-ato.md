# B1829 TCP_INFO delayed-ACK timeout

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED c26a09cf9 | MISSING | low | `TCP_INFO` left `tcpi_ato` zero despite TCP owning the adaptive delayed-ACK interval that governs its ACK timer. | Validated payload arrivals update `TcpConn`'s adaptive interval; the delayed-ACK timer and `tcp_info::populate_conn_at` consume that same capped state. | B1829-tcp-info-delack-ato01 |
