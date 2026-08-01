# C246-behavioural-test-assertions-2

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| NOT-A-BUG | low | `socketpair(AF_UNIX, SOCK_RAW)` succeeds for an unprivileged caller while `AF_INET`/`AF_PACKET` `SOCK_RAW` return EPERM. Looks like a missing capability screen; it is not. | Verified against the reference: the screen belongs to each family's own create operation, and only the INET pair and AF_PACKET install one. `unix_create` accepts SOCK_RAW from any caller and remaps it to SOCK_DGRAM; AF_NETLINK's NORMAL type IS SOCK_RAW. A family-independent SOCK_RAW screen would break every netlink socket in userspace. Pinned by `net::socket_args::tests::only_the_inet_families_and_af_packet_screen_raw_sockets`, whose comment states the trap. | — |
| OPEN | med | Duplicate lane: C246 independently widened `make feature-gate` from `debug-all` (14 of 87 `debug-*` features) to the full derived list, and fixed the five feature-gated blocks that had rotted behind the hole — `hal::zerotrap`'s missing `PAGE_SIZE_BYTES` import, seven `Task::name` reads left over from when it was a plain array, `smoke::memtest::run`'s pre-IrqGate signature, and an aarch64-unguarded import of x86-only statics in `mm-pmm`. B1671 landed the identical fixes first; C246's commit was dropped in full at rebase. Wasted lane. | Root cause: the claim-work greps in CLAUDE.md were run for the grep-assertion ledger row this lane owns, but NOT re-run when the work grew a second front (the build gate) mid-lane. A lane that changes shape needs a fresh claim check for the new area, not just the one it started with. | — |
| OPEN | low | `net` lib tests: one intermittent failure observed in a single run during C246, clean on 3 immediate re-runs. Consistent with the already-filed parallel-execution instability in the curated ledger, not a new defect. | 1538/1538 on three consecutive runs after the one-off. Recorded so the observation is not mistaken for a C246 regression. | — |

## Curated-ledger row this lane touches

The grep-assertion row in `scratch/known_issues.md` ("source-grep assertions in
`socket_control_tests.rs` / `dispatch.rs` …") is NOT closed. C245 + C246 between
them converted the name-query, socketpair and AF_PACKET-option clusters and
replaced the debug-instrumentation tests with the compile gate; the remaining
inventory, re-derived against `origin/main` at this branch point, is:

| File | `include_str!` sites |
|---|---|
| `syscalls/src/net_common.rs` | 26 |
| `syscalls/src/socket_control_tests.rs` | 18 |
| `syscalls/src/recvmsg/vsock_shutdown_tests.rs` | 6 |
| `syscalls/src/socket_fd.rs` | 4 |
| `syscalls/src/socket_control_tests/dispatch.rs` | 4 |
| `syscalls/src/send_user/tests.rs` | 3 |
| `syscalls/src/fcntl_dup_tests.rs` | 2 |
| `syscalls/tests/select_file_ownership_hosted.rs` | 1 |
| `syscalls/tests/ppoll_sigmask_hosted.rs` | 1 |
| `syscalls/src/poll_ownership_tests.rs` | 1 |
| `syscalls/src/getdents_debug_tests.rs` | 1 |
| `net/src/sock/packet_options.rs` | 1 |

`socket_control_tests.rs` is down from 36 sites to 18 and `dispatch.rs` from 10
to 4 across the two lanes.
