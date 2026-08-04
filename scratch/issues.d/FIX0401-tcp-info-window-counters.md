# FIX0401 — TCP_INFO advertised-window counters

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED (pending merge) | DEFECT | low | `TCP_INFO` left the already-owned advertised-window values `tcpi_snd_wnd` and `tcpi_rcv_wnd` zero. | `TcpConn::snd_wnd` is updated from admitted peer TCP headers; `TcpConn::advertised_rcv_wnd` derives the unscaled byte count from the same calculation used while emitting local TCP headers. Focused TCP and syscall ABI tests pass. | FIX0401-tcp-info-window-counters |
