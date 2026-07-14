# Linux Network Completion Plan

Update: 2026-07-14.

This file is the authoritative remaining-work tracker for Linux networking.
`state.md` records the active lane handoff; this file records the complete
campaign. A checked item requires merged code and the evidence listed here.

## Status

| State | Meaning |
|---|---|
| `[ ]` | unclaimed |
| `[~]` | claimed or in progress; branch and commit must be recorded |
| `[x]` | merged to `main`; merge commit and verification recorded |
| `[!]` | blocked by a named external dependency only |

## Rules

- One behaviorally coherent fix per numbered branch and worktree.
- Every branch starts at current `origin/main`, commits all intended files,
  pushes immediately, opens a PR, merges, updates `main`, and is deleted.
- No compatibility shells, false-success paths, shadow state, or deferred
  Linux contracts.
- Syscall files import/validate/encode only. Network policy and state live in
  `crates/kernel/net` or the owning protocol/family crate.
- Every completed item updates this file in the same PR with branch, PR,
  merge commit, tests, both target builds, and smoke status.
- Use hosted tests for the development loop. Run x86 and ARM target builds on
  each kernel branch. The campaign ends with one integrated dual smoke; use
  the user-authorized smoke skip on intermediate pushes after focused gates.
- Linux source and glibc ABI are authoritative. When an old objective differs
  from Linux, correct the objective instead of implementing the mismatch.

## Baseline

Merged network foundation:

- [x] B823 UDP endpoint ownership and multicast/filter groundwork, PR #3083,
  merge `13126593`.
- [x] B824 per-network-namespace INET tables, PR #3084, merge `62b47845`.
- [x] B825 canonical route/rule/interface namespace selection, PR #3085,
  merge `4505f665`.
- [x] B826 IPv6 multicast local admission, PR #3086, merge `094dedb6`.
- [x] B827 classic-filter fault-recoverable import, PR #3087, merge `7bef233a`.
- [x] B828 ICMPv6 error conversion, PR #3088, merge `9259ac24`.
- [x] B829 multicast socket-kind semantics, PR #3089, merge `0f400b2b`.
- [x] B830 INET/TCP socket-filter semantics, PR #3090, merge `478bc037`.
- [x] B831 AF_PACKET namespace/filter/metadata semantics, PR #3091, merge
  `1134fbff`. Hosted net: 431 passed. x86 and ARM target builds passed.

## A. Active Foundation Track

- [x] **N01 real raw IP sockets** - branch `B832-network-raw-ip-sockets`, PR
  #3093, merge `4d08b5a1`.
  Replace AF_INET/AF_INET6 UDP shells with socket-owned raw endpoints in the
  network namespace's canonical INET tables. Implement protocol demux,
  bind/connect/disconnect, device scope, send/sendto/sendmsg, receive and
  source addresses, IPv4 `IP_HDRINCL`, IPv6 checksum handling, filters,
  poll/wakeup, pending errors, close, diagnostics, and hosted tests.
  - [x] N01.1 socket-owned raw4/raw6 endpoints, namespace protocol tables,
    exact receive demux, reassembly, filtering, queueing, poll, and close.
  - [x] N01.2 IPv4/IPv6 arbitrary-protocol transmit, PMTU, fragmentation,
    checksum, and caller-header modes.
  - [x] N01.3 raw socket options, signed/zero `optlen`, fault-recoverable
    import, ICMP filters, and readback.
  - [x] N01.4 ICMP/ICMPv6 pending and extended errors with Linux hardness,
    tuple, namespace, device, wakeup, and queue semantics.
  - [x] N01.5 namespace-scoped immutable `/proc/net/raw` and `raw6` snapshots.
  - [x] N01.6 reject nonlocal/device-inconsistent IPv4 binds and IPv4-mapped
    IPv6 raw binds; preserve namespace-local address ownership.
  - [x] N01.7 implement raw `sendmsg` IP/IPv6 ancillary controls and Linux
    `MSG_OOB`/`MSG_DONTROUTE` behavior instead of accepting ignored input.
  - [x] N01.8 make IPv6 `IPV6_HDRINCL` transmit caller bytes under Linux's
    minimum-length/MTU contract without rewriting or overvalidating headers.
  - [x] N01.9 install route-selected local addresses on connect and enforce
    `SO_BROADCAST` for IPv4 raw connect/send.
  - [x] N01.10 account raw4 receive bytes against `SO_RCVBUF` and report drops.
  - [x] N01.11 encode an enabled IPv6 raw UDP zero checksum as `0xffff`.
  - [x] N01.12 close the raw receive arm versus `SHUT_RD` lost-wakeup race.
  - [x] N01.13 reject overlapping or terminal-shortened IPv4/IPv6 fragment
    queues without panic, stale assembly, or partial packet publication.
  - [x] N01.14 reject raw IPv4/IPv6 receive `MSG_OOB` before queue consumption.
  - [x] N01.15 apply raw IPv4/IPv6 multicast interface, source, hop/TTL, and
    loopback options through the canonical transmit path.
  - [x] N01.16 compile and fragment IPv4 options like Linux, keep socket
    protocol immutable without `IP_HDRINCL`, and route source options by hop.
  - [x] N01.17 enforce complete IPv6 fragment-zero header chains, strict
    per-message interface routing, and true multicast-loop suppression.
  - [x] N01.18 match Linux ancillary length, capability, option-validation,
    and per-message-over-socket precedence rules.
  - Evidence: hosted net 484, procfs 46, syscalls 53; focused raw4 7, raw6 11,
    raw cmsg 5; x86 and ARM release builds passed. x86 smoke reached
    `multi-user.target` and `graphical.target`. User-authorized ARM smoke skip:
    glibc userspace reached systemd, then unrelated services trapped/segfaulted
    and `upower.service` restart-looped until the 600-second timeout.
- [~] **N02 multicast robustness accounting** - branch
  `B833-multicast-robustness`, claim `2e7ee8c9`.
  Preserve successful membership when IGMP/MLD report output fails. Roll back
  only synchronous validation/allocation/filter-setup failures. Consume a
  bounded Linux robustness transmission count regardless of individual xmit
  success; remove the current retry-forever behavior and update tests.
- [ ] **N03 canonical network-namespace lifetime**.
  Replace raw namespace IDs held by tasks, sockets, netlink sockets, and
  namespace fds with one refcounted `NetNamespace` owner. Trigger teardown at
  final owner drop and remove ID-scan/task-table cleanup heuristics. Cover
  clone/unshare/setns/fd/socket lifetime and state destruction races.
- [ ] **N04 common socket-filter family parity**.
  Execute attach/detach/lock semantics and receive filtering for AF_UNIX,
  AF_NETLINK, and AF_VSOCK. Preserve family-specific packet views, positive
  truncation, zero drop, inheritance, lock/error precedence, and tests.

## B. Packet Socket Completion

- [ ] **N05 ingress and egress observation parity**.
  Cover physical, module, loopback, locally generated, and outgoing packet
  paths with correct `sll_pkttype`, L2/L3 views, namespace, device, and filter
  behavior. Prove no duplicate delivery.
- [ ] **N06 packet memberships and device lifecycle**.
  Implement Linux packet memberships including promiscuous/all-multicast,
  interface move/removal behavior, namespace teardown, and close races.
- [ ] **N07 packet options and scalable receive**.
  Audit and implement required `SOL_PACKET` options, statistics, fanout, and
  mmap ring contracts. Split each independently testable contract into its own
  numbered bug branch when implementation begins.

## C. Message I/O Completion

- [ ] **N08 recvfrom row 45**.
  Complete fd/pointer/length/flag errno ordering, copy-fault side effects,
  every supported family, OOB/error-queue interaction, security hooks, and
  syscall-context differential tests.
- [ ] **N09 sendmsg row 46**.
  Complete IP/IPv6 control-message effects, VSOCK destination behavior,
  security hooks, fault ordering, and differential tests.
- [ ] **N10 recvmsg row 47**.
  Complete extended-error origins/control data, IP/IPv6 ancillary data, true
  OOB, VSOCK parity, compat `msghdr`, copy-fault transaction rules, security
  hooks, and differential tests.
- [ ] **N11 recvmmsg row 299**.
  Complete compat `mmsghdr`, restart-block/SA_RESTART behavior, timeout and
  partial-batch fault ordering, cross-protocol errors, OOB, security hooks,
  and differential tests.

## D. Socket Lifecycle Completion

- [ ] **N12 shutdown row 48**.
  Audit and implement Linux validation, errno ordering, half-close behavior,
  wakeups, pending data/errors, and every supported family.
- [ ] **N13 bind row 49**.
  Complete syscall import/error ordering, AF_UNIX/NETLINK/PACKET/VSOCK parity,
  security hooks, and Linux reuse/TIME_WAIT conflict behavior.
- [ ] **N14 listen row 50**.
  Complete fd/type/backlog/error ordering, SYN and accept queue behavior,
  reuseport listener groups, AF_UNIX/VSOCK parity, security hooks, and tests.
- [ ] **N15 getsockname row 51 and getpeername row 52**.
  Complete family-specific names, disconnected states, value-result copyout,
  fault ordering, namespace/scope IDs, and differential tests. Split rows into
  separate branches if either requires behavioral code beyond shared import.
- [ ] **N16 socketpair row 53**.
  Complete type/protocol/flag validation, atomic two-fd publication and
  rollback, UNIX stream/datagram/seqpacket behavior, security hooks, and
  syscall-context tests.

## E. Option Completion

- [ ] **N17 setsockopt row 54**.
  Audit the full Linux option matrix. Complete coercion/optlen/uaccess order,
  capability and security hooks, reuseport BPF, multicast teardown cases,
  raw/packet/family-specific options, and direct differential tests. Use one
  branch per coherent option family.
- [ ] **N18 getsockopt row 55**.
  Complete option coverage, truncation/optlen/copyout-fault ordering,
  capability/security behavior, filter readback, unsupported-family errno,
  teardown states, and differential tests.

## F. Cross-Cutting Correctness

- [ ] **N19 network security hooks**.
  Install Linux-shaped create/bind/connect/listen/send/receive/option hooks in
  one canonical security boundary. Do not duplicate checks in syscall shims.
- [ ] **N20 TCP Linux edge semantics**.
  Complete SYN queue, accept backlog, reuseport listener selection,
  reuse/TIME_WAIT collisions, OOB/urgent data, asynchronous errors, and
  deterministic retransmission/state tests.
- [ ] **N21 namespace/device teardown matrix**.
  Exercise every socket family across interface move, link removal, namespace
  final drop, blocked I/O, poll/epoll, multicast, routes, neighbors, fragments,
  diagnostics, and close.
- [ ] **N22 ABI differential harness**.
  Run equivalent glibc programs on Linux and Oxide for rows 41-55 and 299,
  checking return values, errno precedence, output bytes/lengths, flags,
  ancillary data, blocking, and side effects on both architectures.

## G. Completion Gate

- [ ] All rows 41-55 and 299 have honest `IMPL` evidence in
  `syscall-compliance-matrix.md`; no known gap is hidden in prose.
- [ ] Full hosted network, netlink, security, namespace, procfs, and syscall
  suites pass with no ignored failure relevant to this plan.
- [ ] x86_64 and aarch64 kernel target builds pass from clean prerequisites.
- [ ] Integrated x86 and ARM smoke reach the same user-visible milestone.
- [ ] `boot.txt` has no unexplained network failure, timeout, or fallback.
- [ ] Every plan lane is merged; `main == origin/main`; no plan branch,
  worktree, open PR, uncommitted file, or unpushed commit remains.
