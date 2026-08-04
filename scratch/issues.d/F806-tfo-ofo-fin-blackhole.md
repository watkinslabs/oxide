# F806 — Fast Open out-of-order FIN blackhole detection

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 45f2b1b6a | MISSING | med | The two missing active Fast Open blackhole-detection rungs are implemented: a bare FIN queued out of order before close, and one arriving after local close. | `TcpConn::ooo_buf` now owns payload, urgent metadata, and FIN together; `tcp_conn::active_fastopen::tests::{a_bare_fin_stranded_before_local_close_names_a_fast_open_blackhole,a_bare_fin_arriving_after_local_close_names_a_fast_open_blackhole}`; x86 and ARM smoke pass. | FIX01-F806-tfo-ofo-fin-blackhole |
