# B1827 TCP_INFO maximum pacing rate

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | MISSING | low | `TCP_INFO` leaves `tcpi_max_pacing_rate` zero even though `SO_MAX_PACING_RATE` stores the connection's configured transmission ceiling. | `tcp_info::populate` never reads `InetSocket::opts.generic.max_pacing_rate()`, so listeners and connections both lose the socket-owned value. | B1827-tcp-info-max-pacing-rate |
