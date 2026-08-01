# Known issues

Running ledger of every known breakage, divergence, and open question. Any lane
that finds one adds a row in the same PR that finds it; any lane that fixes one
flips the row to `FIXED` with the SHA and MOVES it to `scratch/fixed-issues.md`
in the same PR. Rows are never deleted, only relocated.

Status: `OPEN` | `IN-PROGRESS <branch>` | `FIXED <sha>`.
Severity: `blocker` (merge gate) | `high` (wrong answer reaching userspace) |
`med` (missing surface) | `low` (hygiene, tooling, cosmetics).

Never delete a row to make the list look shorter. A row with no owner is still
a row.

## Tooling / gates

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | med | `net` test suite is unstable under parallel execution — intermittent failures on BOTH `main` and branches. Weakens every `N/0 passed` claim by an unknown margin. | main 2/12 (`packet_membership_tests::final_close_flushes_every_unique_device_reference`, `sock_rtnl_defer::tests::defer_skips_queueing_when_both_pieces_are_empty`, `packet_ring_v3_tests::raw_loopback_transmit_publishes_one_multicast_record`); B1641 2/30 (`route_metrics_tests::resolved_route_retains_priority_and_complete_metrics`, `net_ns::tests::concurrent_materialization_publishes_one_loopback`). Five distinct tests, all global-state shaped. | — |
| OPEN | med | A `net` test binary can enter a multi-core spin — observed at ~4300% CPU for 20 min, orphaned from a completed run. Distinct from, and more serious than, the intermittent assertion failures above. | Reaped manually during B1641; poisons any concurrent measurement while live. | — |
| OPEN | low | 42 `find(...).unwrap()` source-grep assertions in `socket_control_tests.rs` / `dispatch.rs` fail hard whenever the text they grep moves. Already produced one false "flake" and one real merge break. Convert to behavioural assertions. | B1641 hit this twice; two were converted, the rest remain. | — |
| OPEN | low | Citation debt: repository text must not name/path-link/quote external implementation sources. 273 files carry `.c:NNN`, 113 mention `include/uapi`, 50 carry `.h:NNN`, 10 name the local reference tree by path. | Pre-existing tree-wide; B1641 added zero. | — |
| FIXED C247 | low | `metadata/index.md` counters go stale and collide — index read `D 424` while `D432` was already merged. | `tools/next-branch.sh` derives the number from git refs + merge subjects and maxes against the table; `--check` fails when the table is behind, wired into `make ci` as `counter-check`. Positive control: the check reported `C247 already exists in git` before the table was bumped. | C247 |

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
| IN-PROGRESS B1662 | med | IP/IPv6 options stored-but-unconsumed: ~~`IP_FREEBIND`/`IP_TRANSPARENT` + v6 twins~~ (B1662-a: one screen on every bind path, v6 twins share the inet word, `ip_nonlocal_bind` added), `IP_BIND_ADDRESS_NO_PORT`, `IP_LOCAL_PORT_RANGE` (three allocation sites take the owner, not the socket), router-alert delivery (no fan-out chain), anycast join/leave (routed to the multicast helper), `PKTOPTIONS`. `IP_CHECKSUM` is inert; `IP_RETOPTS` echoes but nothing fills record-route/timestamp on receive. | B1641 gaps 5-10. | — |
| OPEN | low | `recvmmsg` batch rules (UIO_MAXIOV clamp removal, pending-error-before-batch, OOB ends the batch) are verified against the reference but have NO test — the shim is target-gated and no hosted test reaches it. Believed correct, untested. | B1641. | — |
| OPEN | low | Phantom-test gap in `sock_v6.rs` and `sock/{udp,ops,send}.rs` — decision logic sits in target-gated files where `#[cfg(test)]` compiles away silently. | — | — |
| OPEN | low | `socket` crate: `vsock_destination_and_interrupt_errors_match_linux` fails. Pre-existing on `main`. | Confirmed on `main` before and after B1641. | — |
| OPEN | low | `IP_MULTICAST_ALL` now defaults on (reference default), so an unjoined group is delivered. We have no host-level multicast gate equivalent to the reference's, which drops unjoined-group traffic at the IP layer before any socket sees it — so our delivery may be broader than the reference's. Boot reaches `basic.target`; a graphical boot exercising mDNS/LLMNR has not been run. | B1641. | — |

## Keyring

Rows found by B1649 (`add_key`/`request_key`/`keyctl`). Retired rows: `fixed-issues.md`.

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | high | The `request_key` upcall has NEVER run against a real helper: there is no `/sbin/request-key` in the image (`userspace/` and `vendor/` carry zero keyutils references — `umh`'s own selftest uses that path *because* it is guaranteed absent). Every construction therefore ends `ENOENT` -> negate, which is indistinguishable from a box without keyutils installed. The kernel half is complete and exercised by a helper driving the real `keyctl` cores, but the exec path itself is unproven. Fix: ship keyutils in the image, then boot-verify one real construction. | B1649. `construct/tests.rs` drives 25 tests through an injected actor; none of them exec anything. | — |
| OPEN | high | B1579 recorded that a usermode helper started concurrently with early userspace on SMP=2 wedges (kernel-context VFS lookup vs a concurrent user lookup). `request_key` is now a second caller of that machinery, so the hazard is on a user-reachable path. NOT re-verified by B1649 — no boot was run. | B1579's note; unconfirmed either way by B1649. | — |
| IN-PROGRESS B1657/B1658/B1659 | med | `KEYCTL_DH_COMPUTE` **DONE (B1657)**: real `mpi` bignum crate + counter-mode derivation over the `crypt::Digest` table; the capability bit is now computed from the implementing module instead of a hand-kept list. Still EOPNOTSUPP: the `KEYCTL_PKEY_*` family (B1658, needs asymmetric-key parsing) and `KEYCTL_WATCH_KEY` (B1659, needs a `watch_queue`), whose capability bits stay clear until they land. | B1657: 16 `mpi` tests, 5 `crypt::digest`/`sha1` tests, 9 `keyring::tests::dh` tests incl. RFC 3526 group-5 known answers. | — |
| OPEN | med | `fork_keys` / `exec_keys` are verified by build and inspection only. Their call sites are in kernel-gated files (`056_clone.rs`, `exec_transition.rs`) with no extractable decision logic, so no hosted test proves either hook actually fires. `exit_keys` IS covered. Same phantom-test class as the `sock_v6.rs` row above. | B1649. | — |
| OPEN | low | No `/proc/sys/kernel/keys/gc_delay`. Deliberate: `Store::collect()` runs inline with no delay timer, so the knob would gate nothing — and a sysctl that reads back but changes no behaviour is the defect class this project bans. Add the knob only when a deferred gc exists. | B1649, negative result. | — |
| OPEN | low | A named session keyring is NOT joinable by default, including by its own owner: `find_keyring_by_name` checks Search WITHOUT possession, and the mask a named keyring is created with grants View/Read/Link only. So `keyctl session <name>` twice yields two distinct keyrings unless the owner widens the mask first. This matches the reference and is test-pinned, but it is surprising enough that a future lane will read it as a bug. | B1649, `a_named_join_without_search_permission_creates_rather_than_joins`. | — |
