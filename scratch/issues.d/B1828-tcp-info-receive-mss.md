# B1828 TCP_INFO receive MSS

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | MISSING | low | `TCP_INFO` reports `tcpi_rcv_mss` from the peer's advertised receive MSS instead of the locally observed receive MSS used for delayed-ACK decisions. | `tcp_info::populate_conn_at` reads `peer_mss`; validated payload input does not retain an observed receive MSS. | B1828-tcp-info-receive-mss |
