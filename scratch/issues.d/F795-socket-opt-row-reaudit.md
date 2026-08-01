# F795 — re-audit of the socket/sockopt NEEDS-REWORK rows

Re-audit of matrix rows 50 `listen`, 288 `accept4`, 54 `setsockopt`, 55 `getsockopt`.
Every blocker below was verified against the tree at `origin/main` `341ff408f`, not
against a commit message. Rows were rewritten in the same PR. No row was promoted.

## Stale blockers found (the reason this re-audit was needed)

| Status | Row | Stale claim | Verified truth on main |
|---|---|---|---|
| STALE | 50, 288 | TCP_DEFER_ACCEPT completes the handshake and withholds the child; needs a request-sock minisock | FIXED by `B1656`. `net::stack::tcp_reqsk::defers_segment` is called from the production `deliver_tcp_packet_hop` before any state machine; a bare ACK is dropped and the request stays SYN-RECV on its SYN-backlog slot. `cargo test -p net --lib defer` 25/0, ungated. |
| STALE | 54, 55 | TCP_ZEROCOPY_RECEIVE returns ENOPROTOOPT | FIXED by `B1655`. Intercepted in `055_getsockopt/tcp.rs` ahead of the generic value table; drains the receive queue; `mmap(2)` on a TCP socket fd is live. No path returns ENOPROTOOPT for it. |
| STALE | 54, 55 | IP_OPTIONS never emitted on transmit | FIXED by `B1660` for UDP and raw4. Partially stale only: TCP still passes a literal `None`. |
| STALE | 54, 55 | IP/IPV6 families wholly unaudited | `B1662`'s three consumers (nonlocal-bind screen, local-port window, IP_ROUTER_ALERT v4 delivery) are genuinely live on real paths with ungated tests. |

## Open findings (no owner)

| Status | Area | Evidence |
|---|---|---|
| OPEN | TCP fast-open codec has no production caller | `TcpConn::syn_options` hardcodes `fastopen: None`; `fastopen::parse`/`classify` have zero callers outside their own module. No SYN carries a TFO option, no listener validates a cookie, no data-in-SYN path. Sockopt state is stored and read back only. |
| OPEN | IPv6 sticky extension headers stored-only | `IPV6_HOPOPTS`/`RTHDRDSTOPTS`/`RTHDR`/`DSTOPTS` validated then never emitted; `merge_sticky_raw6_control` merges only `multicast_loop` and `traffic_class`, never the `Raw6Control` header fields. Per-message cmsg ext headers DO work on raw6 — sticky ones do not. |
| OPEN | `IPV6_PKTINFO` sticky has no reader anywhere | Written on the set path; no consumer and no getsockopt readback. `Ipv6Opts::nexthop` likewise has zero callers. |
| OPEN | IP_CHECKSUM inert | Correctly modelled as the recv-cmsg flag and it reaches a consumer, but the producer is hardcoded off (`recvmsg::inet` sets `checksum: None`); `RxMeta.checksum` is never `Some` outside a test. `SO_NO_CHECK` has zero consumers. |
| OPEN | TCP does not emit IP_OPTIONS | `send_tcp_ipv4_segment_in` passes `None` where Linux puts IP_OPTIONS on TCP segments. |
| OPEN | IPV6 router-alert has no delivery chain | The selector is stored and admission-screened, but `router_alert` implements only `v4_present`/`v4_deliver` — the v6 half is join bookkeeping with no delivery, unlike v4. |
| OPEN | SOL_IP stored-but-unconsumed | `IP_NODEFRAG`, `IP_RECVERR_RFC4884`, `IP_UNICAST_IF` (never influences route/source selection), `IP_TRANSPARENT` (bind permission only — no TPROXY delivery or reply-source behaviour). |
| OPEN | SOL_IPV6 stored-but-unconsumed | `IPV6_ADDR_PREFERENCES`, `IPV6_USE_MIN_MTU`, `IPV6_MTU`, `IPV6_UNICAST_IF`, `IPV6_AUTOFLOWLABEL`, `IPV6_ROUTER_ALERT_ISOLATE`. |
| OPEN | SOL_PACKET stored-but-unconsumed | `PACKET_COPY_THRESH`, `PACKET_TX_HAS_OFF`, `PACKET_QDISC_BYPASS`. Rest of the family is live. |
| OPEN | Options missing entirely | `IP_PROTOCOL` has no set-path arm (settable on raw sockets in Linux); `IPV6_JOIN_ANYCAST`/`IPV6_LEAVE_ANYCAST` are declared in uapi with no set-path arm. |
| OPEN | listen/accept4 admission ladders are unreachable from `cargo test` | `050_listen.rs` and `043_accept.rs` carry `#![cfg(target_os = "oxide-kernel")]`, and `net::sock::ops` (security hook, `somaxconn` lookup, family branch) is kernel-gated. Blocks promotion of rows 50 and 288 on permissions, error ordering, and user-copy fault cases. Needs the `F792` socket(2) treatment: extract to one ungated owner. |
| OPEN | accept4 copy-out failure relies on `Drop`, untested | On `copy_sockaddr_to_user` failure the INET path returns the errno and drops `accepted.new_sock`, where the VSOCK sibling calls `net::vsock::close(&conn)` explicitly. The child is already popped off `accept_q` with its backlog slot released. No test asserts the errno or that the slot is not leaked. Not shown to be a defect — untested. |
| OPEN | `syscalls::socket_control_tests` proves nothing about behaviour | It "covers" `050_listen.rs` by `include_str!` source-text grep (asserting the file contains `fd_file(fd)`, `Errno::Enotsock`); `043_accept.rs` is not covered at all. A gate that cannot fail on a behaviour change. |
| OPEN | `syscalls/src/tcp_zerocopy/receive.rs` has no hosted coverage | `#![cfg(target_os = "oxide-kernel")]` by design; the remap, copy-out and frame-lifetime code is uncovered and only the pure planner it delegates to is tested. |

## Negative results (first-class — save the next lane the work)

- TCP_ZEROCOPY_RECEIVE does **not** violate the refcounted-frame mapping rule. `009_mmap.rs` passes the window as a FILE BACKING with `phys_base = None`; `TcpZcWindow` implements `vmm::FileBacking`, so the fault path inc_refs per PTE and teardown dec_refs. No `PhysRange`, no `map_phys_range`, no `glue_mmap(phys_base=Some(..))` on the path. Checked because a refcounted RAM frame mapped as `PhysRange` is a known free-while-mapped UAF class in this tree.
- The defer-accept minisock is not dead code. Both the RX hook and the 100ms periodic `tcp_reqsk_tick` have production call sites; only the `_at` snapshot wrapper is `#[cfg(test)]`.
- No phantom test modules were found among those cited by rows 50/54/55/288 — each was confirmed to compile and execute.
- The deferred request is a full heap `TcpEntry` allocated at SYN time, not a slim `request_sock`, and there are no SYN cookies. Externally observable behaviour matches Linux; per-half-open memory economics do not. Recorded as a structural note, not a correctness blocker.
