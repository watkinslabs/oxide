# B1828 TCP_INFO receive MSS

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 7b56347ba | MISSING | low | `TCP_INFO` reported `tcpi_rcv_mss` from the peer's advertised receive MSS instead of the locally observed receive MSS used for delayed-ACK decisions. | `TcpConn` now owns the receiver-MSS observation and its live receive-window policy hint; `tcp_info::populate_conn_at` projects that state. | B1828-tcp-info-receive-mss |
