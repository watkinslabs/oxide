# B1715 — the socket control syscalls get one ungated routing owner

Cluster: "tests that cannot run, and tests that cannot fail". Closes the
curated row that opens `` `syscalls::socket_control_tests` proves nothing about
behaviour `` — it "covered" `050_listen.rs` by `include_str!` source-text grep
(asserting the file contains `fd_file(fd)`, `Errno::Enotsock`); `043_accept.rs`
was not covered at all.

The fd-classification ladder shared by `shutdown(2)` 48, `accept(2)` 43 /
`accept4(2)` 288, `listen(2)` 50 and `getpeername(2)` 52 now lives in the
ungated `syscalls::sock_route`, and each slot file calls it through
`net_common::classify`, which resolves the fd exactly once. Hosted tests drive
the same code the kernel runs; the four grep assertions that could not fail are
gone, replaced by 12 behavioural ones (syscalls `--lib` 1199 -> 1209 passed;
workspace 13036 -> 13046).

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED B1715 | med | `accept`/`accept4` on an AF_NETLINK fd returned ENOTSOCK where the reference returns EOPNOTSUPP — netlink's protocol operations carry the "no such operation" stub for accept, exactly as they do for listen (which this tree already got right). The old shim never classified netlink at all on the accept path, so a netlink socket fell through to the not-a-socket tail. | `sock_route::tests::netlink_refuses_listen_and_accept_as_unsupported_not_as_a_non_socket`; positive control: returning `Enotsock` from the netlink arm turns it RED. | B1715 |
| OPEN | low | `listen(2)` on an AF_NETLINK socket refuses with EOPNOTSUPP without running the network security admission hook first. The reference evaluates `security_socket_listen` before the protocol's listen operation, so a policy that denies the listen should report EACCES and does not. `shutdown` and the name query do not have this gap — both reach the netlink owner, which admits and then refuses. Not fixed here: the admission needs the netlink socket's namespace and family threaded to `security::network::evaluate`, which is a change to the netlink owner rather than to the routing ladder. | `sock_route::route` returns `Err(Eopnotsupp)` for `(Listen, Netlink)` with no admission call; `net::sock::listen` evaluates the hook for every other family. | unclaimed |
| OPEN | low | "Each control slot resolves its fd exactly once" is no longer asserted by anything. It used to be a source grep (`source.matches("fd_file(fd)").count() == 1`) — an assertion that could not fail on a behaviour change but did name a real property: a second lookup can land on a different open file description after a concurrent close/reopen recycles the slot. It is now structural (`net_common::classify` is the only caller of `fd_file` on these paths and returns the pinned file), and not reachable hosted: the fd table lookup is `sched::live::current`-gated. What would settle it is a guest probe that closes and reopens an fd from a second thread across a `getpeername`, or an fd-table fault-injection seam. | `net_common::classify` is `#[cfg(target_os = "oxide-kernel")]` because `fd_file` is. | unclaimed |
| OPEN | low | `043_accept.rs`'s blocking half is still uncovered hosted — the per-listener park (TCP/AF_UNIX/VSOCK arm, `schedule()`, `remove_current`), the `sock_intr_errno` rung and the `SO_RCVTIMEO` deadline all sit in the kernel-gated slot. Only the admission head (EBADF, the flag word, ENOTSOCK, EOPNOTSUPP) moved to the ungated owner. The interrupted-wait rung keeps its `include_str!` assertion in `net_common.rs` (`every_blocking_socket_receive_wait_routes_through_sock_intr_errno`), which is still a source grep — left in place because the decision it names has no ungated seam yet. Settling it needs the wait loop restructured around an ungated "what does this wait return" decision, the way `net_errno::sock_intr_errno` already is for the errno alone. | `crates/kernel/syscalls/src/043_accept.rs` `accept_common` loop. | unclaimed |
| OPEN | low | `accept4` copy-out failure still relies on `Drop` for the INET path and no test asserts the backlog slot is not leaked — the curated row that opens "accept4 copy-out failure relies on `Drop`, untested" is untouched by this PR. It needs a hosted seam for the copy-out itself, which is `uaccess`-gated. | Curated ledger row; `043_accept.rs` `copy_sockaddr_to_user` arm. | unclaimed |
