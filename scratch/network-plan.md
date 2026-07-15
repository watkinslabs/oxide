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
  - [x] N01.19 serialize raw IPv4/IPv6 bind and `SO_BINDTODEVICE` under one
    socket lifecycle lock; prove endpoint and common device state cannot diverge
    with deterministic bind-versus-device-change races. B846, PR #3119, merge
    `61bc95f6`; hosted net 608 and focused raw4/raw6 contention tests passed;
    x86 and ARM target checks passed.
  - [x] N01.20 implement Linux ICMPv4 fragmentation-needed semantics across
    UDP, raw, and TCP: nonfatal common mapping, per-socket PMTU modes, pending
    and extended errors, raw `IP_HDRINCL` payload, TCP sequence validation,
    MSS/retransmit response, and route-cache acceptance/bypass rules. Active on
    `B847-icmpv4-pmtu-error-semantics`, PR #3121, merge `b5195a57`.
    Implementation adds output-route keyed
    PMTU cache expiry/refresh/floor behavior, IPv4/IPv6 mode separation on
    dual-stack UDP sockets, and family-correct socket-owned TCP transmit policy.
    Hosted net 641, syscalls 59, and procfs 47 passed; x86 and ARM target checks
    passed.
  - Evidence: hosted net 484, procfs 46, syscalls 53; focused raw4 7, raw6 11,
    raw cmsg 5; x86 and ARM release builds passed. x86 smoke reached
    `multi-user.target` and `graphical.target`. User-authorized ARM smoke skip:
    glibc userspace reached systemd, then unrelated services trapped/segfaulted
    and `upower.service` restart-looped until the 600-second timeout.
- [x] **N02 multicast robustness accounting** - branch
  `B833-multicast-robustness`, PR #3095, merge `85be212d`.
  Preserve successful membership when IGMP/MLD report output fails. Roll back
  only synchronous validation/allocation/filter-setup failures. Consume a
  bounded Linux robustness transmission count regardless of individual xmit
  success; remove the current retry-forever behavior and update tests.
  Evidence: hosted net 497; focused ordering/lifecycle 9 and learned QRV 2;
  net/procfs/syscalls checks and x86 release build passed. B834 replaced the
  obsolete musl vDSO toolchain path; B835 enforces each architecture's Linux
  symbol versions and ELF contract. x86 and ARM release builds pass.
  - [x] N02.1 move multicast family, socket-kind, scalar-option, and membership
    policy out of syscall shims into canonical net work functions; prove IPv4
    and IPv6 membership on an unbound socket does not allocate a port. B845,
    PR #3117, merge `9a076593`; hosted net 606 and syscalls 59 passed, including
    14 focused net/syscall multicast tests; x86 and ARM release builds passed.
- [~] **N03 canonical network-namespace lifetime**.
  Replace raw namespace IDs held by tasks, sockets, netlink sockets, and
  namespace fds with one refcounted `NetNamespace` owner. Trigger teardown at
  final owner drop and remove ID-scan/task-table cleanup heuristics. Cover
  clone/unshare/setns/fd/socket lifetime and state destruction races.
  - [x] N03.1 introduce a dependency-neutral network-namespace owner with
    immutable monotonic ID, owning user namespace, stable nsfs identity, weak
    live registry, init owner, and install-once final-drop callback. B836,
    PR #3100, merge `0d26f077`; lifecycle tests 2, package checks and touched
    spec-lint gates passed. B837 context contracts and deterministic final-drop
    races merged in PR #3102 at `50ce37e4`; 3 tests and package checks passed.
  - [x] N03.2 replace task `AtomicU64` storage with an owned namespace handle;
    clone atomically, swap under one lock, and release explicitly on task exit
    so pidfds retaining reaped tasks cannot retain namespace membership.
    B838, PR #3105, merge `16132232`.
  - [x] N03.3 make proc namespace links and nsfs inodes retain the concrete
    network owner instead of reconstructing an owner from a numeric ID.
    B838, PR #3105, merge `16132232`; nsfds retain concrete owners across task
    exit and setns never reconstructs a dead numeric ID.
  - [x] N03.4 wire clone, `CLONE_NEWNET`, unshare, and setns publication and
    rollback through owned handles; publish loopback before the new owner.
    B838, PR #3105, merge `16132232`; loopback materializes before task owner
    publication and combined creation stages fallible work first.
  - [x] N03.5 make INET/UNIX/PACKET, NETLINK, and VSOCK sockets retain the
    concrete owner; accepted sockets clone the listener owner directly.
    B838, PR #3105, merge `16132232`; socketpair and accepted TCP, UNIX, and
    VSOCK sockets clone the retained owner.
  - [x] N03.6 make `SIOCGSKNS` return the resolved socket's namespace and make
    listns enumerate the live registry, including fd-only and socket-only owners.
    B838, PR #3105, merge `16132232`; both operations consume concrete owners
    instead of task-table reconstruction.
  - [x] N03.7 enqueue final-drop teardown exactly once and quiesce interfaces
    before removing addresses, neighbors, multicast, fragments, routes/rules,
    transport tables, UNIX state, sysctls, and registry metadata.
    B840, PR #3107, merge `71457583`; hosted net 513, procfs 47, sched 137,
    syscalls 53, softirq 6, namespace 3, Virtio net 19, and sysfs 48 pass;
    x86 and ARM target builds pass. Smoke reached `basic.target` on x86 in
    70s and ARM in 129s; ARM includes the final AP-ready publication barrier.
  - [~] N03.8 prove final-drop, pidfd, nsfd, passed-socket, blocked-I/O, ingress,
    teardown, SIOCGSKNS, listns, and task-owner swap races in hosted and loom
    tests; run full network/namespace/syscall suites and dual target builds.
    B841, PR #3109, merge `7d6c2abb` proves the core lifecycle protocol;
    N03.8.2-N03.8.5 remain separate fixes.
    - [x] N03.8.1 add real Loom infrastructure and model callback publication,
      lookup/drop/claim, coalesced pending work, reaper park/wake, and task-owner
      swap; add deterministic linearization tests. B841. Loom exposed the
      destructive pending-bit lost-wakeup race; monotonic publication/consumption
      generations now preserve concurrent notification across harvest and park.
      PR #3109, merge `7d6c2abb`.
    - [x] N03.8.2 capture an ingress generation/owner lease before physical RX
      dequeue and invalidate/wait old generations before interface return to init.
      B842, PR #3111, merge `f8d5c20a`; Virtio and Linux-module RX hold one
      concrete-owner lease across L2/L3 delivery, Virtio descriptors carry
      assignment generations, stale completions drop and retag on repost,
      departed address policy clears, and reassignment re-raises NetRx.
    - [~] N03.8.3 retain the concrete namespace owner in private-loopback drain
      snapshots until every queued packet finishes dispatch. Active on
      `B848-netns-loopback-owner-pin`. Owner-bearing snapshots consume the
      complete queue drain; deterministic final-drop/UDP dispatch test, hosted
      net 642, and x86/ARM target checks pass.
    - [ ] N03.8.4 install `SIOCGSKNS` namespace fds with `FD_CLOEXEC` atomically
      through fd reservation/install; prove no exec leak or close/reuse race.
    - [ ] N03.8.5 prove socket, passed-socket, nsfd, pidfd, listns, blocked-I/O,
      materialization, and ingress owner retention with controlled schedules.
    - [x] N03.8.6 unregister physical devices through their canonical current
      namespace before destroying Virtio queue/runtime state; prove a device
      assigned outside init cannot leave a published dead interface. B843,
      PR #3113, merge `8c077249`; teardown completion and resume-pending
      generations serialize namespace return against driver uninstall, while
      failed unpublish preserves queue, runtime, and reset ownership.
    - [x] N03.8.7 serialize interface control-plane mutation against lifecycle
      close so address, route, flag, and multicast operations that began before
      close cannot republish departed-namespace state after teardown removal.
      B844, PR #3115, merge `11b75c13`; rank-125 per-stack RTNL, exact namespace
      and interface-generation leases, ordered control notifications, deferred
      driver effects, route/rule/address canonical state, RA/DAD and IGMP/MLD
      workers, and teardown drains prevent cross-generation publication. Hosted
      gates: net 598, netlink 89, syscalls 53, Virtio 25, namespace 3, netdev
      modules 4; `make x86`, `make arm`, diff check, and changed-file caps passed.
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
  Install Linux-shaped create/bind/connect/listen/accept/send/receive/shutdown,
  name-query, socketpair, option, and ioctl hooks in one canonical security
  boundary. Make netfilter rules, verdicts, and counters canonical per network
  namespace and pass ingress lease ownership into hook evaluation. Do not
  duplicate checks in syscall shims.
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

## G. Remaining Network Syscalls

- [ ] **N23 sendmmsg row 307**.
  Complete Linux vector validation, partial-batch/error ordering, timeout and
  blocking behavior, compat `mmsghdr`, control-message handling, security
  hooks, and differential tests. Null vectors must not report false success.
- [ ] **N24 network ioctl rows 16 and 288**.
  Complete socket and interface ioctl command coverage, mutable interface
  properties, namespace/device ownership, capability and security checks,
  uaccess/error ordering, compat ABI, and differential tests.
- [ ] **N25 TCP blocking-wait linearization**.
  Arm and recheck connect/write wait conditions without SYN-ACK, RST, ACK,
  close, timeout, or signal lost-wakeup windows; split the over-cap wait module.
- [ ] **N26 VSOCK blocking-wait linearization**.
  Serialize receive terminal-state and send credit/close publication against
  wait arming; prove retry-to-park transitions cannot lose the final wake.
- [ ] **N27 NETLINK pending-error receive parity**.
  Route read, recvfrom, and recvmsg through one queue/error decision so queued
  datagrams precede pending errors and empty blocking readers wake on errors.

## H. Completion Gate

- [ ] All network rows 16, 41-55, 288, 299, and 307 have honest `IMPL` evidence in
  `syscall-compliance-matrix.md`; no known gap is hidden in prose.
- [ ] Full hosted network, netlink, security, namespace, procfs, and syscall
  suites pass with no ignored failure relevant to this plan.
- [ ] x86_64 and aarch64 kernel target builds pass from clean prerequisites.
- [ ] Integrated x86 and ARM smoke reach the same user-visible milestone.
- [ ] `boot.txt` has no unexplained network failure, timeout, or fallback.
- [ ] Every plan lane is merged; `main == origin/main`; no plan branch,
  worktree, open PR, uncommitted file, or unpushed commit remains.
