# Known issues

Running ledger of every known breakage, divergence, and open question. Any lane
that finds one adds a row in the same PR that finds it; any lane that fixes one
flips the row to `FIXED` with the SHA and deletes it on the next sweep.

Status: `OPEN` | `IN-PROGRESS <branch>` | `FIXED <sha>`.
Severity: `blocker` (merge gate) | `high` (wrong answer reaching userspace) |
`med` (missing surface) | `low` (hygiene, tooling, cosmetics).

Never delete a row to make the list look shorter. A row with no owner is still
a row.

## Tooling / gates

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | high | Routine gate set compiles NO feature-gated code, so a branch that does not build can pass every check. Fix: add `xtask kernel --arch <a> --features debug-boot` to the gate set. | Proven by reinstating the `kmain` tuple bug: default build 0 errors, `--features debug-boot` reports `E0308` and fails `kmain`. | — |
| OPEN | med | `net` test suite is unstable under parallel execution — intermittent failures on BOTH `main` and branches. Weakens every `N/0 passed` claim by an unknown margin. | main 2/12 (`packet_membership_tests::final_close_flushes_every_unique_device_reference`, `sock_rtnl_defer::tests::defer_skips_queueing_when_both_pieces_are_empty`, `packet_ring_v3_tests::raw_loopback_transmit_publishes_one_multicast_record`); B1641 2/30 (`route_metrics_tests::resolved_route_retains_priority_and_complete_metrics`, `net_ns::tests::concurrent_materialization_publishes_one_loopback`). Five distinct tests, all global-state shaped. | — |
| OPEN | med | A `net` test binary can enter a multi-core spin — observed at ~4300% CPU for 20 min, orphaned from a completed run. Distinct from, and more serious than, the intermittent assertion failures above. | Reaped manually during B1641; poisons any concurrent measurement while live. | — |
| OPEN | low | 42 `find(...).unwrap()` source-grep assertions in `socket_control_tests.rs` / `dispatch.rs` fail hard whenever the text they grep moves. Already produced one false "flake" and one real merge break. Convert to behavioural assertions. | B1641 hit this twice; two were converted, the rest remain. | — |
| OPEN | low | Citation debt: repository text must not name/path-link/quote external implementation sources. 273 files carry `.c:NNN`, 113 mention `include/uapi`, 50 carry `.h:NNN`, 10 name the local reference tree by path. | Pre-existing tree-wide; B1641 added zero. | — |
| OPEN | low | `metadata/index.md` counters go stale and collide — index read `D 424` while `D432` was already merged. | Same hazard the file's own note records for `C238`. | — |

## Net / socket

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | high | `drain_loopback()` runs a full receive traversal inline on the caller's stack across 32 call sites (send, poll, recv, shutdown, setsockopt, `Drop`). The reference queues to a per-CPU backlog and drains later on its own stack; TX and RX are never on one stack there. Worth ~2768 B on every such chain. | Deepest aarch64 chain: TX 13 frames / 6496 B + hinge 4 / 544 + RX 6 / 2768. NEGATIVE RESULT: a runtime re-entrancy guard does NOT help — the depth walker follows static call edges, so only breaking the edge through the softirq function pointer helps. | — |
| OPEN | med | aarch64 stack-depth margin is thin: 12688 B against a 13000 B ceiling (312 B). Remaining >=576 B frames belong to other lanes: `sys_sendmmsg` 1008, `send_prepared` 880, `deliver_rx_ipv6_payload` 768, `packet::deliver` 704, `TxDispatch::enqueue` 576. | Frame-shaving cannot fix this class; see `drain_loopback` above. | — |
| OPEN | med | `TCP_DEFER_ACCEPT` deviation: we complete the handshake and withhold the connection from `accept`; the reference drops the bare ACK so the peer keeps retransmitting. Accept-side contract is identical, but a peer inspecting its own socket sees ESTABLISHED where the reference shows retransmitting. Needs a request-sock minisock. | B1641, test-backed on the accept side. | — |
| OPEN | med | `TCP_ZEROCOPY_RECEIVE` returns ENOPROTOOPT. Needs mm-side page mapping into the caller's address space. | Genuine deviation, not a config answer. | — |
| OPEN | med | Fast-open family (`TCP_FASTOPEN`, `_KEY`, `_NO_COOKIE`) stored with nothing consuming it — no TFO handshake exists. `TCP_FASTOPEN_CONNECT -> EOPNOTSUPP` is CORRECT and test-pinned (matches a zero enable bit). | B1641. | — |
| OPEN | med | `IP_OPTIONS` on transmit and IPv6 sticky extension headers on transmit: validated and readable, never emitted. Inventory: `Ipv4Hdr` has no options member; fixed 20-byte prepend in `push_ipv4_header*`; `IPV4_HDR_LEN` at six sites in `xmit_ipv4_l4_with_policy` incl. fragmentation maths and headroom; five callers; LSRR needs the route lookup retargeted at the compiled first hop. `raw4/tx.rs` is the only place writing `ihl > 5`. | B1641. | — |
| OPEN | med | AF_UNIX `MSG_OOB` (send and receive) not implemented. | B1641. | — |
| OPEN | med | IP/IPv6 options stored-but-unconsumed: `IP_FREEBIND`/`IP_TRANSPARENT` + v6 twins (the local-address screen they relax exists only on the raw/ping bind path), `IP_BIND_ADDRESS_NO_PORT`, `IP_LOCAL_PORT_RANGE` (three allocation sites take the owner, not the socket), router-alert delivery (no fan-out chain), anycast join/leave (routed to the multicast helper), `PKTOPTIONS`. `IP_CHECKSUM` is inert; `IP_RETOPTS` echoes but nothing fills record-route/timestamp on receive. | B1641 gaps 5-10. | — |
| OPEN | low | `recvmmsg` batch rules (UIO_MAXIOV clamp removal, pending-error-before-batch, OOB ends the batch) are verified against the reference but have NO test — the shim is target-gated and no hosted test reaches it. Believed correct, untested. | B1641. | — |
| OPEN | low | Phantom-test gap in `sock_v6.rs` and `sock/{udp,ops,send}.rs` — decision logic sits in target-gated files where `#[cfg(test)]` compiles away silently. | — | — |
| OPEN | low | `socket` crate: `vsock_destination_and_interrupt_errors_match_linux` fails. Pre-existing on `main`. | Confirmed on `main` before and after B1641. | — |
| OPEN | low | `IP_MULTICAST_ALL` now defaults on (reference default), so an unjoined group is delivered. We have no host-level multicast gate equivalent to the reference's, which drops unjoined-group traffic at the IP layer before any socket sees it — so our delivery may be broader than the reference's. Boot reaches `basic.target`; a graphical boot exercising mDNS/LLMNR has not been run. | B1641. | — |

## Process

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | med | Verification that returns green without exercising what it claims to. Two confirmed instances: `procfs/ctl.rs` is target-gated so `cargo check` compiled none of it (break appeared only in the kernel build); a set-based duplicate-test check that structurally could not detect duplicates (a set dedupes the very thing being looked for). Prefer a positive control — reinstate the defect and confirm the check goes red. | B1641. | — |
