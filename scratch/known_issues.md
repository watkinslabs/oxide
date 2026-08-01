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

## Keyring

Rows found by B1649 (`add_key`/`request_key`/`keyctl`). The FIXED rows are kept
so the next lane can see what shape these defects took — three of them were
subsystems that compiled, tested and shipped with nothing calling them.

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | high | The `request_key` upcall has NEVER run against a real helper: there is no `/sbin/request-key` in the image (`userspace/` and `vendor/` carry zero keyutils references — `umh`'s own selftest uses that path *because* it is guaranteed absent). Every construction therefore ends `ENOENT` -> negate, which is indistinguishable from a box without keyutils installed. The kernel half is complete and exercised by a helper driving the real `keyctl` cores, but the exec path itself is unproven. Fix: ship keyutils in the image, then boot-verify one real construction. | B1649. `construct/tests.rs` drives 25 tests through an injected actor; none of them exec anything. | — |
| OPEN | high | B1579 recorded that a usermode helper started concurrently with early userspace on SMP=2 wedges (kernel-context VFS lookup vs a concurrent user lookup). `request_key` is now a second caller of that machinery, so the hazard is on a user-reachable path. NOT re-verified by B1649 — no boot was run. | B1579's note; unconfirmed either way by B1649. | — |
| OPEN | med | `KEYCTL_DH_COMPUTE`, the `KEYCTL_PKEY_*` family and `KEYCTL_WATCH_KEY` return EOPNOTSUPP. They need MPI bignum, asymmetric-key parsing and a `watch_queue` respectively. `KEYCTL_CAPABILITIES` truthfully clears the matching bits, so a caller that probes before use is not misled — but this is still absent surface, not a config answer. | B1649; capability bytes asserted in `tests/rings.rs`. | — |
| OPEN | med | `fork_keys` / `exec_keys` are verified by build and inspection only. Their call sites are in kernel-gated files (`056_clone.rs`, `exec_transition.rs`) with no extractable decision logic, so no hosted test proves either hook actually fires. `exit_keys` IS covered. Same phantom-test class as the `sock_v6.rs` row above. | B1649. | — |
| OPEN | low | No `/proc/sys/kernel/keys/gc_delay`. Deliberate: `Store::collect()` runs inline with no delay timer, so the knob would gate nothing — and a sysctl that reads back but changes no behaviour is the defect class this project bans. Add the knob only when a deferred gc exists. | B1649, negative result. | — |
| OPEN | low | A named session keyring is NOT joinable by default, including by its own owner: `find_keyring_by_name` checks Search WITHOUT possession, and the mask a named keyring is created with grants View/Read/Link only. So `keyctl session <name>` twice yields two distinct keyrings unless the owner widens the mask first. This matches the reference and is test-pinned, but it is surprising enough that a future lane will read it as a bug. | B1649, `a_named_join_without_search_permission_creates_rather_than_joins`. | — |
| FIXED 579d405bd | high | `inherit_session` had NO caller outside its own test. No forked child ever inherited a session keyring; nothing purged a dead task's entries, so a RECYCLED tid inherited the previous occupant's keys, and every task touching `@s`/`@t`/`@p` leaked a keyring plus its quota charge permanently. | B1649. Now `lifecycle::{fork,exec,exit,fsids_changed}` wired at clone/execve/exit/commit_creds; `exit_purges_the_tid_and_frees_the_keyring`, `exit_refunds_the_quota_charge`. | B1649 |
| FIXED 244c9e5f6 | high | Between minting an authorisation token and handing the helper the keyring holding it, NEITHER was reachable from any gc root. Any concurrent `collect()` — an unrelated task unlinking a key is enough — destroyed both and stranded the requester on a key no helper could then answer. A real intermittent production failure, surfaced only because the hosted tests run in parallel against the global store. | B1649. `Store::collect` now roots live tokens and the keyring linking them. | B1649 |
| FIXED 244c9e5f6 | high | `KEYCTL_GET_PERSISTENT` aliased the USER keyring — wrong owner, wrong lifetime (the user keyring dies with the last session; the persistent one must outlive logout), and gated on `CAP_SYS_ADMIN` where the reference uses `CAP_SETUID`. | B1649. Now a real `_persistent.<uid>` in a `.persistent_register`, destination mandatory, expiry refreshed per use; `the_persistent_keyring_is_not_the_user_keyring`. | B1649 |
| FIXED 244c9e5f6 | high | `KEYCTL_SEARCH` flattened every failure to ENOKEY, discarding WHY the search failed. That both hid EACCES/EKEYREVOKED/EKEYEXPIRED from callers and made negative-key caching impossible, so an unresolvable name would re-run the helper on every request. Three pre-existing tests asserted the flattened behaviour and encoded the wrong belief. | B1649. `ops/search.rs` now reproduces the skip-reason propagation and the `success > ENOKEY > EAGAIN > other` merge. | B1649 |
| FIXED 244c9e5f6 | med | `request_key` did not distinguish `callout == NULL` from `callout == ""`; both suppressed construction. The empty string must upcall. | B1649, `an_empty_callout_string_still_upcalls`. | B1649 |
| FIXED 244c9e5f6 | med | `KEYCTL_REVOKE` did not retry with `KEY_NEED_SETATTR` on EACCES, so a key whose mask grants Setattr but not Write could not be withdrawn by its holder; and it used a partial lookup, so a second revoke reported EACCES instead of EKEYREVOKED. | B1649, `revoke_falls_back_to_setattr_permission`, `revoking_twice_reports_the_key_is_already_revoked`. | B1649 |
| FIXED 244c9e5f6 | med | `KEYCTL_SET_TIMEOUT` and `KEYCTL_GET_SECURITY` had no authorisation-token path, so a helper could not bound or inspect the key it was asked to build. `KEYCTL_JOIN_SESSION_KEYRING` accepted a `.`-prefixed name, which would place a caller inside `.persistent_register`. | B1649, `set_timeout_accepts_the_authorisation_token_instead_of_setattr`, `a_dot_prefixed_session_name_is_refused`. | B1649 |
| FIXED 68f197dc4 | med | `/proc/keys` and `/proc/key-users` were empty static stubs and `/proc/sys/kernel/keys/*` did not exist at all. | B1649. Both live and per-reader filtered; four ceilings plus `persistent_keyring_expiry` bound to the live values `key_alloc` and `KEYCTL_GET_PERSISTENT` consult. | B1649 |

## Process

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | med | Two lanes splitting one file for the size cap along different axes produces a conflict where the STALE side looks plausible. B1641 and B1649 both split `procfs/ctl.rs`; B1649's copy of the `net` subtree predated B1641 making `rmem_default`/`wmem_default` live and adding `tcp_rmem`/`tcp_wmem`, so resolving line-by-line would have silently reverted two leaves to dead `Const` and deleted two more, with nothing red. Rule: take the other side wholesale and re-apply your own delta; verify by MULTISET count, not name set. | B1649 merge of `27cdb991f`; 100 declarations both sides, none dropped, none duplicated. | — |
| OPEN | med | Verification that returns green without exercising what it claims to. Two confirmed instances: `procfs/ctl.rs` is target-gated so `cargo check` compiled none of it (break appeared only in the kernel build); a set-based duplicate-test check that structurally could not detect duplicates (a set dedupes the very thing being looked for). Prefer a positive control — reinstate the defect and confirm the check goes red. | B1641. | — |
