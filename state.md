# state - network completion

Update: 2026-07-14.

## Current lane

- `main`: `9d271d3e`, synchronized with `origin/main`.
- N01 merged in PR #3093; branch and worktree deleted.
- N01 closure tracking merged in PR #3094.
- N02 multicast robustness accounting merged in PR #3095 at `85be212d`.
- B834 uses the GNU aarch64 target for reproducible vDSO generation.
- B835 adds strict per-architecture vDSO ABI validation.
- N03.1 owner foundation merged in PR #3100 at `0d26f077`.
- B837 owner contracts and race hardening merged in PR #3102 at `50ce37e4`.
- N03.2-N03.6 owner migration merged in PR #3105 at `16132232`; closure
  tracking merged in PR #3106 at `9d271d3e`.
- N03.7 final-drop teardown is active on `B840-netns-final-drop-teardown`.

## Implemented

- Socket-owned raw4/raw6 namespace tables, demux, reassembly, filtering,
  queues, poll, shutdown, close, bind/connect, diagnostics, and errors.
- Linux-shaped raw4/raw6 transmit, PMTU, fragmentation, caller headers,
  multicast policy, checksums, options, receive accounting, and error queues.
- Raw `sendmsg` IPv4/IPv6 ancillary parsing and immutable per-message controls,
  including source routing, extension headers, interface overrides, flags,
  capability checks, and Linux error/length precedence.
- Review corrections cover conflicting fragment queues, receive lost wakeups,
  IPv4 option compilation, source-route wire destinations, direct on-link
  `MSG_DONTROUTE`, weak-host source selection, IPv6 fragment-zero completeness,
  arbitrary-protocol fragmentation, and 65,535-byte payload enforcement.
- Tasks, proc namespace links, nsfs nodes, INET/UNIX/PACKET/NETLINK/VSOCK
  sockets, and accepted sockets retain concrete network namespace owners.
- Task exit releases membership before zombie publication; pidfds cannot keep
  namespace membership alive, while nsfds and passed sockets retain it.
- clone/unshare/setns stage owned-handle publication; new namespaces publish
  loopback before task membership and capability checks use the retained owner.
- `SIOCGSKNS` returns the socket owner and listns includes fd-only/socket-only
  owners from the canonical live registry.

## Verification

- Full hosted: net 484, procfs 46, syscalls 53; zero failures.
- Focused: raw4 controls 7, raw6 transmit 11, raw cmsg parser 5.
- `cargo check -p net -p procfs -p syscalls`: passed.
- `make x86`: passed.
- `make arm`: passed.
- `git diff --check`: passed; changed Rust files remain below 500 lines.
- N02 hosted network suite: 497 passed, zero failures.
- N02 focused ordering/lifecycle races: 9 passed; learned QRV exhaustion: 2 passed.
- N02 `cargo check -p net -p procfs -p syscalls`: passed.
- N02 `make x86`: passed.
- B834 vDSO ELF/type/export checks: passed.
- B834 `make x86` and `make arm`: passed.
- B835 exact versioned-export, ELF layout, relocation, and tool-isolation
  checks: passed.
- B835 hosted HAL tests: shared 12, ARM 47, x86 74; zero failures.
- B835 `make x86` and `make arm`: passed.
- B836 namespace-owner lifecycle and callback tests: 2 passed, zero failures.
- B836 `cargo check -p network-namespace -p sync`: passed.
- B836 touched code, docs, and length spec-lint gates: clean.
- B836 `git diff --check`: passed; all new Rust files are below 100 lines.
- B837 deterministic publication/drop/harvest tests: 3 passed, zero failures.
- B837 package checks, touched code/length lint, and `git diff --check`: passed.
- B838 serial hosted: net 502, sched 137, syscalls 53, sysfs 48, netlink 60,
  nscg 12, procfs 46; zero failures.
- B838 x86_64 and aarch64 syscall target checks passed.
- B838 integrated package check and `git diff --check` passed.
- B838 `make x86` and `make arm` passed.
- B838 smoke reached `basic.target` on first real attempt: x86 74s, ARM 108s.
- B840 hosted: net 513, procfs 47, sched 137, syscalls 53, softirq 6,
  network-namespace 3, drv-virtio-net 19, sysfs 48; zero failures.
- B840 final `make x86` and `make arm`: passed.
- B840 smoke: x86 reached `basic.target` in 70s before the final ARM-only
  startup barrier; final x86 retry reached GDM but missed the serial marker,
  then exposed the existing VFS name-walk lock flake. Final ARM reached
  `basic.target` in 129s after the AP-ready publication race was removed.

## Remaining network work

- B840 N03.7 final-drop teardown commit, PR, merge, and closure.
- N03.8 lifecycle/race proof, then N04-N22.

## First resume command

`cd /home/nd/oxide/kernel && git pull --ff-only && rg -n 'N03' scratch/network-plan.md`
