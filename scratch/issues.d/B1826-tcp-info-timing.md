# B1826 TCP_INFO activity timing

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | MISSING | low | `TCP_INFO` leaves the activity-age fields `tcpi_last_data_sent`, `tcpi_last_data_recv`, and `tcpi_last_ack_recv` zero because TCP retains no distinct clocks for those events. | `tcp_info::populate_conn` leaves all three ABI fields at default; existing `last_rx_ns` is only keepalive state and cannot distinguish data from ACK activity. | B1826-tcp-info-timing |
