# B1825 TCP_INFO PMTU/MSS projection

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 7368538ce | MISSING | low | `TCP_INFO` did not project the connection's synchronized path MTU, leaving `tcpi_pmtu` zero after active open, passive open, PMTU refresh, or a learned PMTU reduction. | The TCP connection now owns the synchronized PMTU cookie used by `TCP_INFO`; active/passive PMTU policy, refresh, learned reduction, and ABI projection regressions cover it. | B1825-tcp-info-pmtu-mss |
