# B1823 — TCP_INFO negotiated option bits

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED (pending merge) | DEFECT | low | `TCP_INFO` left negotiated timestamp, SACK, window-scale, and ECN option bits zero despite `TcpConn` owning those negotiated facts. | Linux projects `rx_opt.tstamp_ok`, SACK, `wscale_ok`, and negotiated ECN into `tcpi_options`; local equivalents are `ts_enabled`, `sack_ok`, `wscale_ok`, and `ecn_enabled`. Focused ABI tests, serial full-net tests, both feature targets, and both smoke boots pass. | B1823-tcp-info-options |
| OPEN | DEFECT | med | `cargo test -p net --lib` can deadlock under its default parallelism: packet-ring tests spin in `sock::packet::register_packet` while netdev tests spin waiting for `netdev::tx_dispatch` completion. | B1823 full-net run stayed CPU-active for more than four minutes; debugger backtraces named `packet_ring_v12_tests::receive_delivery_uses_ring_as_the_only_canonical_destination`, `packet_tests::packet_protocol`, and `netdev::tx_dispatch::wait`. | unowned |
