# B1653 — net hosted-test global state

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | low | `crates/kernel/net/src/vsock/conn.rs` is past the 500-line split cutoff (`08§7`), so further connection state has nowhere to go. Pre-existing: 503 lines on `origin/main`, 509 after B1653 added one `AtomicBool` plus its doc. | `wc -l` on `origin/main` vs B1653. | — |
| OPEN | low | Hosted `Spinlock` waits are now bounded by a yield, but `netdev::tx_dispatch::wait()` is still a spin-wait by construction: with `--test-threads 32` it is the dominant cost of the `net` suite (~1.7 s pure-spin at 3770 % CPU → ~7-10 s at ~200 % CPU). A condvar-backed hosted wait would recover the wall time. | `gdb -p` on the wedged binary: 30-odd threads in `tx_dispatch::wait` / `deliver`'s `PACKET_REGISTRY.lock`. Timings measured on the B1653 lane. | — |
| OPEN | low | `sync/hosted` (the yield in `spin_relax::relax`) is opted into per consumer crate. `net`, `sched`, `slab` and `klog` have it; every other crate's hosted tests still pure-spin and carry the same livelock exposure. | B1653 enabled it for `net` only, after reproducing the livelock there. | — |
