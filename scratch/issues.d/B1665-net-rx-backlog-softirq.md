# B1665 — net RX backlog + NET_RX softirq

Two curated `## Net / socket` rows are closed by this branch and are NOT
repeated here; the PR body names them for the integration owner to move to
`scratch/fixed-issues.md`:

- `drain_loopback()` runs a full receive traversal inline on the caller's stack
  across 32 call sites (high).
- aarch64 stack-depth margin is thin: 12688 B against a 13000 B ceiling (med).

New rows found while doing that work:

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | low | The loadable-module `netif_rx` ABI shim delivers a C driver's frame inline on the calling driver's stack instead of queueing it to the per-CPU backlog, so a Linux module's receive path keeps the old TX/RX-on-one-stack shape. Needs the backlog item to carry an L2 frame plus the caller's ingress generation, which the loopback-fed path does not. | Found while converting the loopback path in B1665. `modules::linux_netdev::core::netif_rx` measures 9920 B on aarch64 — under the ceiling, so not urgent, but it is the last inline receive traversal in the tree. | — |
| OPEN | low | A frame sitting in the receive backlog no longer holds an ingress lease, so a namespace teardown racing the drain completes and the queued frame is dropped at delivery instead of being delivered first. This matches the reference (a device that stops running has its backlog discarded) and is a deliberate change from the retained-lease snapshot the inline drain used, recorded so it is not later read as a regression. | B1665; `frames_queued_for_a_down_interface_are_dropped_at_delivery` pins the drop, `net_ns::lifetime_tests` still pins the retained-lease teardown contract. | — |
| OPEN | high | `cargo test -p net` does not build on `main`: three ungated modules import gated ones. `sock_v6_name` imports `crate::sock`; `ipv4_options`, `send_control` and `raw4/tx` import `crate::sock_opts`; both targets are gated `any(target_os = "oxide-kernel", test, feature = "hosted")`, so the plain (non-`test`, no-feature) lib build that `cargo test` also produces fails to resolve them. Hosted verification for every net lane is blocked unless `--features hosted` is passed, which masks it. The fix belongs to whoever owns the gating design for `sock_opts` — either ungate it or gate its ungated consumers — not to a passing lane. | Landed with C245 (`d20295381`, `sock_v6_name`) and B1660 (`ipv4_options`/`send_control`/`raw4`). Positive control: `cargo test -p net` fails to compile at `origin/main` `80e6adf05`; `cargo test -p net --features hosted` passes (1591 tests). Gating `sock_v6_name` alone fixes half of it; gating `ipv4_options` alone just moves the error to `send_control.rs` and `raw4/tx.rs`. | — |
