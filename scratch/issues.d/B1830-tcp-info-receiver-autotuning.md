# B1830 TCP_INFO receiver autotuning

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | MISSING | low | `TCP_INFO` left receiver-window threshold, receiver RTT, and receive-space telemetry absent or reported receive-buffer capacity rather than the TCP receive owners. | `TcpConn` had no receiver RTT/space samples, did not retain the advertised-window threshold, and `tcp_info::populate_conn_at` returned `rcv_buf_cap` as `tcpi_rcv_space`. | B1830-tcp-info-receiver-autotuning01 |
