# B1712 — TCP fast open: the client half (deferral, cookie cache, blackhole)

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | med | **Two of the four blackhole-detection rungs the reference has are not expressible here, and are not implemented.** Implemented: the third consecutive retransmit timeout on a fast-opened connection, and an out-of-sequence reset on one that has received no data. Not implemented: (a) an out-of-order FIN arriving after `close`, and (b) the ofo-queue check that calls the path a blackhole when the only out-of-order segment is a bare FIN. Both need the out-of-order queue to record which segments carried FIN; `TcpConn::ooo_buf` is a `BTreeMap<u32, Vec<u8>>` of payload only, so a FIN sitting out of order is not represented at all. Adding it is a change to ordinary receive, not to fast open. | `crates/kernel/net/src/tcp_conn/types.rs` `ooo_buf`/`ooo_urgent` carry no flags; `tcp_conn/io.rs` drops a FIN's flag on the out-of-order path. The two rungs that ARE implemented are pinned by `tcp_conn::active_fastopen::tests::a_third_consecutive_timeout_on_a_fast_open_names_the_path_a_blackhole` and `TcpConn::fastopen_reset_is_blackhole`. | unclaimed |
| OPEN | low | **The blackhole reset does not exclude a loopback route.** The reference clears the recurrence count only when the confirming connection's device is not loopback, on the grounds that a loopback success proves nothing about the middlebox on the real path. Here `drain_client` resets on any confirming connection that received data. Deliberate: the alternative is threading the egress device into the drain, and a host whose only fast open is over loopback has no real path to protect. | `stack/tcp_fastopen.rs drain_client`; `tcp_fastopen::ns::tests::a_configured_timeout_makes_a_detection_pause_the_namespace` pins the reset itself, not the device rule. | unclaimed |
| OPEN | low | **`ClientCache` records `syn_loss`/`last_syn_loss_ns` and nothing reads them.** The reference records the same two fields and only exports them through the tcp_metrics netlink family, which does not exist here. They are kept because they are part of the cache's contract and because the netlink family will want them; `ClientCache::syn_loss` exists so the recording is at least observable from a test. | `tcp_fastopen/cache.rs`; `cache::tests::recurring_unanswered_fast_open_syns_are_counted_and_a_success_clears_them`. No production reader. | unclaimed |
| OPEN | med | **The socket-layer arms that carry out a deferral are target-gated, so no hosted test asserts that `connect` returns without a SYN.** The decision (`tcp_fastopen::client::decide`), the state it is fed (`sock::tcp_fastopen::plan`), and the mechanism it drives (`TcpConn::active_open_fastopen`) are each covered hosted. The hop between them — `connect_admission::commit` returning `Ok(())` on `TcpOpen::Deferred`, `commit_write` opening with the payload, `send_fastopen::send` choosing between `EINPROGRESS` and a byte count — is inside `#[cfg(target_os = "oxide-kernel")]` and can only be exercised by a boot. Same class as the B1710 row about `054_setsockopt/tcp.rs`. | `sock/connect_admission.rs:1`, `sock/send_fastopen.rs` (declared under `#[cfg(target_os = "oxide-kernel")]` in `sock.rs`). Workspace test total 6291 -> 6376 with none of those lines compiled by `cargo test`. | unclaimed |
| OPEN | low | **`connect(AF_UNSPEC)` on an unconnected TCP socket returns `EINVAL` where the reference returns 0.** Pre-existing and untouched: `SockKind::TcpInit` falls to `Disc::Bad` in `sock::ops::connect_admitted`. This PR does clear a pending fast-open deferral on that path, so a socket cannot be left holding a destination nothing will open to, but the errno is unchanged. | `sock/ops.rs` `RemoteAddr::Unspec` arm. Confirmed against the reference's `tcp_disconnect` on a `TCP_CLOSE` socket. | unclaimed |
| OPEN | low | **`cargo test -p nscg` fails 2 of 57 on `main`, unchanged by this PR.** `proc_ns::tests::capability_walk_uses_concrete_user_parent_owners` and `proc_ns::tests::network_proc_link_retains_exact_owner_after_task_exit`. Reproduced on a detached worktree at `origin/main` (b1e969cf1) before any of this PR's changes. Recorded so the next lane running the full workspace does not read it as its own breakage. | `git worktree add --detach /tmp/b1712-base origin/main && cargo test -p nscg` -> `FAILED. 55 passed; 2 failed`. Identical on this branch. | unclaimed |
| OPEN | low | **`TCP_INFO` is still mostly unpopulated, and this PR filled exactly two more fields.** `tcpi_data_segs_in` and the `tcpi_fastopen_client_fail` bitfield now carry real values because the client half produced them. The other ~40 zero fields (`tcpi_bytes_acked`, `tcpi_segs_out`, `tcpi_delivery_rate`, …) are untouched and still report zero. | `crates/kernel/syscalls/src/tcp_info.rs populate`. | unclaimed |
| OPEN | low | **A stamp written into `ClientCache` from a clock other than the one it is read with reads as stale, not as fresh.** `get`/`set` age entries with `now_ns.wrapping_sub(stamp_ns) >= ENTRY_TIMEOUT_NS`, so a stamp in the future underflows to a huge age and the entry reads as a miss. Safe in the direction that matters — a miss opens the ordinary way — and every production caller uses `crate::tcp_conn::ka_now_ns()`. Recorded because it cost a test failure that looked like a wiring bug. | `tcp_fastopen/cache.rs get`; `sock::tcp_fastopen::tests` originally stamped with a literal and read back with `ka_now_ns()`. | won't fix |
| OPEN | low | **The B1710 incremental-compilation miscompile did not recur.** This PR added five new cross-module helpers in `net` and touched `sock_opts`'s neighbours; every run here was `CARGO_INCREMENTAL=0`, and a final incremental `cargo test -p net` was clean too. The `#[inline]` mitigation on `tcp_fastopen::queue::clamp_qlen` is untouched and is still the only thing standing between the bug and a recurrence. B1710's reproduction was not re-run. | `cargo test -p net --features hosted` — 1901 passed, incremental and not. | unclaimed |

## What landed

- `TCP_FASTOPEN_CONNECT` defers the handshake: `connect` commits the destination,
  publishes the names `getpeername` reports, and returns 0 without sending a SYN. A
  second `connect` on such a socket reports `EISCONN`; `connect(AF_UNSPEC)` withdraws it.
  `poll` already reported `EPOLLOUT` for `SockKind::TcpInit`, which is what tells the
  program to write — verified, not changed.
- `MSG_FASTOPEN` on `sendto`/`sendmsg` does connect-and-send in one call. Blocking: the
  full byte count, whether or not the bytes rode the SYN. Non-blocking: the bytes the SYN
  carried, or `EINPROGRESS` when it carried none. `EOPNOTSUPP` when the client enable bit
  is clear or the call named the unspecified address; `EISCONN`/`EALREADY` on a socket
  that already has a connection.
- Client cookie cache, per namespace, keyed by address pair, with the reference's bucket
  chains, reclaim depth of 5, and one-hour staleness horizon.
- `net.ipv4.tcp_fastopen_blackhole_timeout_sec`, defaulting to 0 (off), with its consumer:
  a namespace-wide pause that doubles per recurrence to 64x the base and is cleared by a
  fast open that carries data over the same path.
- `TFO_CLIENT_NO_COOKIE` now has its consumer: it is one of the three independent sources
  that license putting data in a SYN with no cookie, beside `TCP_FASTOPEN_NO_COOKIE` and
  the route metric.
- The fallback property is pinned exhaustively rather than case by case:
  `client_tests::no_combination_of_client_state_ever_refuses_the_connection` enumerates
  the whole state cross-product, and
  `active_fastopen_tests::every_answer_to_a_fast_open_leaves_an_established_connection`
  does the same over every answer a peer can give.

## Positive controls (each reinstated, RED confirmed, restored, GREEN confirmed)

| Defect reinstated | Went RED |
|---|---|
| `decide` ignores the blackhole pause | `client::tests::{a_blackholed_path_sends_a_bare_syn…, a_blackhole_outranks…, no_combination_of_client_state_ever_refuses_the_connection}` |
| the SYN retransmit keeps the fast-open option | `active_fastopen::tests::a_retransmitted_syn_goes_out_bare_and_alone` |
| the queued data is sent behind the SYN during the handshake | `active_fastopen::tests::a_retransmitted_syn_goes_out_bare_and_alone` |
| the cookie-cache chain grows without reclaiming | `cache::tests::{a_chain_stops_growing_at_the_reclaim_depth, the_chain_reclaims_its_least_recently_refreshed_entry}` |
| the pause doubles without a ceiling | `blackhole::tests::the_pause_stops_doubling_at_sixty_four_times_the_base` |
| an unsolicited cookie is believed | `learn::tests::a_cookie_nobody_asked_for_is_ignored` |

## Curated-ledger rewrites this PR requires

Whoever folds this drop file rewrites, rather than flips, the remaining fast-open row in
`scratch/known_issues.md`:

- The row reading `Fast-open family (TCP_FASTOPEN, _KEY, _NO_COOKIE) stored with nothing
  consuming it — no TFO handshake exists. TCP_FASTOPEN_CONNECT -> EOPNOTSUPP is CORRECT
  and test-pinned` is now wrong in every clause. Both halves of the handshake exist. The
  server takes data from a SYN and mints/verifies cookies (B1711); the client defers on
  `TCP_FASTOPEN_CONNECT`, puts data in the SYN on `MSG_FASTOPEN`, caches cookies per
  destination and pauses itself on a blackholed path (this PR). `TCP_FASTOPEN_CONNECT`
  succeeds by default and returns `EOPNOTSUPP` only when an administrator clears the
  client bit. What remains open is the four rows above, none of which is "nothing
  consumes it".
- The B1710/B1711 rows carrying `net.ipv4.tcp_fastopen_blackhole_timeout_sec still does
  not exist, and TCP_FASTOPEN_CONNECT still defers nothing` and `TFO_CLIENT_NO_COOKIE …
  has no reader` are **resolved** by this PR and may be flipped rather than rewritten.
