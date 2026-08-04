# B1823 — TCP_INFO negotiated option bits

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | DEFECT | med | `cargo test -p net --lib` can deadlock under its default parallelism: packet-ring tests spin in `sock::packet::register_packet` while netdev tests spin waiting for `netdev::tx_dispatch` completion. | B1823 full-net run stayed CPU-active for more than four minutes; debugger backtraces named `packet_ring_v12_tests::receive_delivery_uses_ring_as_the_only_canonical_destination`, `packet_tests::packet_protocol`, and `netdev::tx_dispatch::wait`. | unowned |
