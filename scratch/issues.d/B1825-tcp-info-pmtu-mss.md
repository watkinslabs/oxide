# B1825 TCP_INFO PMTU/MSS projection

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | MISSING | low | `TCP_INFO` does not project the connection's synchronized path MTU, leaving `tcpi_pmtu` zero after active open, passive open, PMTU refresh, or a learned PMTU reduction. | `tcp_info::populate_conn` leaves the ABI field at its default while TCP retains the send MSS and PMTU policy separately. | B1825-tcp-info-pmtu-mss |
