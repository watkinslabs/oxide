# F804 — Fast Open blackhole loopback reset

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED (this PR) | DEFECT | low | **A confirming Fast Open success over loopback cleared the namespace blackhole recurrence.** The drain path now resolves the connection's existing selected route at confirmation time and reads the selected interface's canonical IFF_LOOPBACK flag; only non-loopback (or absent) egress clears the recurrence, matching Linux. | stack::tcp_fastopen_tests covers loopback and absent-egress classification; focused Fast Open tests, feature gate, and paired smoke pass. | F804 |
