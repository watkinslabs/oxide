# Linux Network Completion Plan

Update: 2026-07-15.

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
- [x] **N03 canonical network-namespace lifetime**.
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
  - [x] N03.8 prove final-drop, pidfd, nsfd, passed-socket, blocked-I/O, ingress,
    teardown, SIOCGSKNS, listns, and task-owner swap races in hosted and loom
    tests; run full network/namespace/syscall suites and dual target builds.
    B841, PR #3109, merge `7d6c2abb` proves the core lifecycle protocol;
    N03.8.2-N03.8.5 landed as separate fixes.
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
    - [x] N03.8.3 retain the concrete namespace owner in private-loopback drain
      snapshots until every queued packet finishes dispatch. B848, PR #3123,
      merge `603c32bc`. Owner-bearing snapshots consume the
      complete queue drain; deterministic final-drop/UDP dispatch test, hosted
      net 642, and x86/ARM target checks pass.
    - [x] N03.8.4 install `SIOCGSKNS` namespace fds with `FD_CLOEXEC` atomically
      through fd reservation/install; prove no exec leak or close/reuse race.
      B849, PR #3125, merge `ab29967e`. Single-lock file/CLOEXEC publication,
      exec and close/limit/reuse tests, hosted syscalls 62, VFS reservation 5,
      and x86/ARM target checks pass.
    - [x] N03.8.5 prove socket, passed-socket, nsfd, pidfd, listns, blocked-I/O,
      materialization, and ingress owner retention with controlled schedules.
      - [x] N03.8.5a materialization lookup-first versus final-drop/claim-first.
        B850, PR #3127, merge `5b249311`. Barrier-controlled production
        lookup/materialization orderings prove a resolved owner blocks teardown
        claim and a claimed ID publishes no state; hosted net 643 and x86/ARM
        target checks pass.
      - [x] N03.8.5b socket publication, passive-child, and final-file owner
        schedules.
        - [x] N03.8.5b.i retain concrete namespace ownership in TCP transport
          reservations; listener close atomically rejects new children, removes
          SYN-RECV and completed-unaccepted children, and preserves children
          transferred by accept. B851, PR #3129, merge `d83ffe82`; hosted net
          651 and x86/ARM target checks pass.
        - [x] N03.8.5b.ii publish socket, socketpair, and accepted descriptors
          with `FD_CLOEXEC` atomically. B852, PR #3130, merge `40d0cf56`;
          socket, ordinary/VSOCK/io_uring accept, and the existing socketpair
          reservation path have atomic descriptor-flag publication. Hosted
          syscalls 70, including a concurrent exec/publication schedule, and
          x86/ARM target checks passed.
        - [x] N03.8.5b.iii run VSOCK endpoint cleanup from final file release,
          idempotently shared with socket-object drop. B853, PR #3132, merge
          `6e4e4123`; exact-Arc listener/connection teardown, atomic inbound
          publication, duplicate tuple rejection, transport-terminal ordering,
          syscall-duration File pins, and real duplicate/final-fput schedules.
          Hosted net 665, syscalls 72, and x86/ARM target checks passed.
        - [x] N03.8.5b.iv prove ordinary and accepted INET, UNIX, NETLINK, and
          VSOCK ownership through real File/FdTable close and active-syscall
          schedules. Final fput is synchronous; no RCU barrier is required. B854,
          PR #3133, merge `1d4e3ef4`: read,
          writev, send, receive, bind, listen, name, option, poll, select, and
          `F_DUPFD` routes retain the setup File; INET, accepted INET, UNIX,
          accepted UNIX, NETLINK, and VSOCK are receiving real File/FdTable
          close, failed-publication, final-drop, exact-reuse, and production-call
          schedules. Current hosted gates: socket 23, net 714, netlink 101,
          syscalls 87, fs 114, select ownership 3, VFS vectored I/O 16, write limits 4,
          mount-readonly 4, fd-table duplication 3, and x86/ARM target checks.
          VFS library has one
          unrelated baseline failure,
          `tests_d4b::t1b_idmap_chown_in`, reproduced unchanged on `main`.
      - [x] N03.8.5c passed-socket receive-install versus discard/SCM-GC.
        B855, PR #3134, merge `84d0a1fd`. Stream, datagram, seqpacket, and
        unaccepted-child final
        release drops unread `GcRights` outside queue locks and immediately runs
        canonical SCM collection. Hosted receive-fd batch publication takes explicit
        `FdTable`, limit, CLOEXEC, files, and copyout callbacks while the syscall
        wrapper retains current-task and uaccess ownership. Tests prove receive-first
        roots the passed socket through fd publication; zero control capacity,
        `EMFILE`, and copy fault preserve an installed prefix, roll back the
        current reservation, discard the suffix, set `MSG_CTRUNC`, and collect
        newly unreachable cycles; `MSG_PEEK` installs duplicate descriptors
        while retaining queued rights. The implementation reuses `GcRights::take_files`,
        `GcTransferGuard`, `collect_scm_rights`, and
        `FdTable::scm_install_fd`; no ownership registry was added. Hosted net
        719, socket 31, syscalls 88, VFS SCM install 3, focused SCM receive 8,
        and SCM-GC 12 passed; x86/ARM target checks and concurrency review passed.
        - [x] N03.8.5c.i restore the missing immediate canonical collection
          after stream, unaccepted-stream, datagram-queue, seqpacket, and
          datagram-pair final release drops unread rights outside queue locks.
          B861, PR #3140, commits `3446a7a0d`, `366a252ca`, `faf428a23`, and
          `b432f7185`, calls the
          canonical collector after each outside-lock rights drop and adds
          direct release-boundary tests for all five paths. Focused SCM passed
          30/30, SCM stress 100/100, AF_UNIX stress 50/50 at 32 threads, full
          net 735/735, and x86_64/aarch64 kernel builds passed. Intermediate
          smoke skipped under the standing user authorization.
      - [x] N03.8.5d nsfd fget/setns versus close/reuse. B863, PR #3142,
        commits `d4dfb4b8c` and `ff47b76d5`, moves namespace-fd resolution into the canonical
        `nscg::setns_from_fd` work function and retains one `Arc<File>` through
        inode downcast and namespace installation. Deterministic pin-first and
        close/reuse-first schedules prove exact descriptor reuse cannot retarget
        an active network `setns`, while completed reuse is visible to a later
        lookup. The pin also retains the concrete non-init network owner, and
        an empty-slot schedule proves `EBADF` precedes type validation and later
        reuse. nscg 15/15 and 100/100 parallel stress passed; x86_64 and
        aarch64 kernel builds passed. Intermediate smoke skipped under the
        standing user authorization.
      - [x] N03.8.5e pidfd exit/open and listns retained-snapshot schedules.
        - [x] N03.8.5e.i give pidfd open a dedicated process/thread identity
          acquisition boundary; prove open/exit/reap/PID-reuse schedules and
          publish the pidfd with `FD_CLOEXEC` atomically. B864 gives `sched`
          canonical `PidIdentity` and `ThreadGroup` owners and gives the
          dedicated `pidfd` crate the VFS object/open work function. Exact
          process or thread acquisition precedes exit/reap; the identity, exit
          snapshot, and targeted poll source survive task release and PID reuse.
          Leader readiness waits for final thread exit, reaped descriptors add
          `POLLHUP`, and clone membership commits only after fallible setup.
          File plus close-on-exec publication is one fd-table operation. Tests
          cover `ENOENT` process/thread selection, `ESRCH` released targets,
          retained `PIDFD_GET_INFO`, failed-clone membership, concurrent exits,
          close/reuse, clone/clone3 prepare-commit rollback, and atomic
          publication. Scheduler 149/149, pidfd 6/6, VFS fd-table 5/5,
          syscalls 88/88, pidfd and scheduler pidfd stress 50/50 each at 32
          threads, changed-owner spec-lint, length lint, and x86_64/aarch64
          kernel builds pass. Branch `B864-pidfd-open-lifetime`.
        - [x] N03.8.5e.ii replace numeric-only non-network namespace identity
          with concrete task/nsfd owners, namespace-owned live indexes, and
          exit-before-zombie release. B865 gives cgroup, IPC, PID, time, user,
          and UTS identities canonical owners with weak live/nsfs indexes; tasks
          retain one exact namespace set, nsfds retain typed owners, PID mappings
          retain weak ancestor identities, and exit drops membership before
          publishing `Zombie`. IPC and UTS state is finalizer-owned. VFS keeps
          mount lifetime on `Arc<MntNamespace>` and retains it through reserve,
          graft, copy, snapshot, commit, abort, procfs open state, and detached
          `open_tree` A-to-B rebind. Incomplete TIME namespace operations return
          `EINVAL` until e.iv supplies clock semantics. Evidence: namespace
          identity 6/6 and 100-run race stress; nscg 26/26 and 100-run stress;
          scheduler 158/158; IPC 40/40; syscall library 88/88 and hosted
          namespace entry 10/10; procfs 48/48; devfs 15/15; pidfd 6/6; netlink
          101/101; net 738/738; network namespace 3/3 and Loom 6/6; 44/44
          changed VFS integration targets; mount ownership 100/100 and detached
          tree ownership 100/100; x86_64/aarch64 kernel builds; x86 smoke reached
          `basic.target` in 74s on the immediate rerun after one transient
          systemd `dbus.socket` `EBADF` abort. ARM smoke is host-blocked before
          QEMU by absent vendored arm64-efi GRUB modules. Full VFS library is
          112/113 on both B865 and main due the pre-existing idmapped-chown
          `EINVAL`. Branch `B865-nonnet-ns-ownership`.
        - [x] N03.8.5e.iii move listns enumeration into one namespace work
          function and retain concrete namespace owners through ID publication;
          prove snapshot-first/final-drop-first schedules. B866 moves task and
          network enumeration into `nscg::listns_snapshot`; its private entries
          retain exact non-network, mount, and network owners until syscall ID
          copyout finishes. Controlled snapshot-first/final-drop-first schedules
          pass 100/100; nscg 28/28, syscall library 88/88, and x86_64/aarch64
          kernel builds pass. Branch `B866-listns-retained-snapshot`.
        - [x] N03.8.5e.iv replace task/nsfs-inode enumeration with Linux's one
          global monotonic eight-kind `ns_id` space and active global, per-type,
          and direct-user-owner trees; complete visibility filtering, nsfd-only
          discovery, real TIME_NS clocks, extension/reserved-field handling,
          structural cursor/pagination semantics, per-element copy faults, and
          errno-order differential coverage. B867 installs one canonical
          eight-kind registry with distinct active-membership and lifetime-pin
          handles, owner activity propagation, permanent initial namespaces,
          and atomic global/per-kind/direct-owner indexes. Mount and network
          namespaces publish their concrete identities through that registry;
          `listns` retains lifetime pins without extending active membership.
          TIME namespaces use native monotonic/boottime offsets, opener
          credentials authorize procfs writes, and POSIX clocks use native
          realtime, monotonic, boottime, TAI, and process/thread CPU domains.
          Extension/reserved validation, structural cursor pagination,
          per-element faults, empty pages, visibility, owner filtering, and
          snapshot/final-drop schedules pass. Namespace identity 10/10, nscg
          37/37, procfs 58/58, scheduler 172/172, syscalls 98/98, workspace
          check, and x86_64/aarch64 kernel builds pass. Branch
          `B867-listns-linux-active-trees`.
      - [x] N03.8.5f blocked INET/UNIX/NETLINK/VSOCK I/O versus fd close.
        `B868-network-blocked-io-close` retains the original File across active
        operations; TCP/VSOCK connect and accept, TCP/UNIX send, and
        NETLINK/VSOCK/UNIX receive use lock-coupled wait arms with terminal
        state published before wake. AF_UNIX stream queues provide partial
        progress while datagram/seqpacket queues preserve record atomicity.
        Hosted net 748/748, netlink 104/104, socket 31/31, syscalls 99/99, and
        x86_64/aarch64 kernel builds pass.
      - [x] N03.8.5g ingress lease/final-drop delivery and stale-generation rejection.
        `B869-network-ingress-final-drop` closes loopback admission before purge,
        acquires the exact loopback lease before dequeue, publishes namespace
        final-drop completion only after owner fields drop, and rejects stale
        Linux NAPI/skb and Virtio RX work by interface generation plus exact
        Virtio device owner. Controlled snapshot-first/final-drop-first,
        destructor-notification, stale NAPI/skb, and equal-generation reprobe
        schedules pass. Hosted net 752/752, Linux netdev 10/10, Virtio net
        26/26, namespace 4/4, namespace Loom 8/8, workspace check, KPI header
        smokes, and x86_64/aarch64 kernel builds pass. x86 smoke reached
        `basic.target` in 66s; ARM smoke is host-blocked before QEMU by missing
        vendored `arm64-efi` GRUB modules.
      - [x] N03.8.5h composed Loom owner-retention matrix.
        `B870-network-owner-loom-matrix` composes materialized-state, socket,
        passed-socket, nsfd, pidfd, listns, blocked-I/O, and ingress retention
        against production registry lookup/final-drop/claim and reaper
        publication/harvest transitions. Every boundary covers operation-first
        and close-first schedules, retained lookup pins, no resurrection, and
        exactly one harvest/claim winner. Hosted net 752/752, namespace 4/4,
        full Loom net 756/756 and namespace 9/9, workspace check, and
        x86_64/aarch64 kernel builds pass.
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
- [x] **N04 common socket-filter family parity**.
  Execute attach/detach/lock semantics and receive filtering for AF_UNIX,
  AF_NETLINK, and AF_VSOCK. Preserve family-specific packet views, positive
  truncation, zero drop, inheritance, lock/error precedence, and tests.
  `B871-network-common-socket-filter`, PR #3151, merge `22bbe738f`. Common
  File-pinned option dispatch now owns attach, detach,
  lock, and lock readback for all three families. AF_UNIX datagram/seqpacket,
  raw AF_NETLINK datagram, and AF_VSOCK `OP_RW` receive paths execute the
  receiver filter with Linux zero-drop and positive-truncation semantics.
  Accepted UNIX/VSOCK children inherit listener filter state, while live VSOCK
  sockets and connections share one canonical filter owner. Hosted net 758/758,
  netlink 105/105, socket 33/33, and syscalls 99/99 passed; workspace check and
  x86_64/aarch64 kernel builds passed. x86 smoke reached `basic.target` in 60s
  on the immediate retry after the documented intermittent systemd failure.
  ARM smoke is host-blocked before QEMU by missing vendored `arm64-efi` GRUB
  modules; the aarch64 kernel build passed.

## B. Packet Socket Completion

- [x] **N05 ingress and egress observation parity**.
  Cover physical, module, loopback, locally generated, and outgoing packet
  paths with correct `sll_pkttype`, L2/L3 views, namespace, device, and filter
  behavior. Prove no duplicate delivery.
  `B872-network-packet-observation`, PR #3152, merge `ff04b77f3`.
  One AF_PACKET observation owner now receives exact retained
  ingress/egress device generations across Virtio, Linux netdev modules,
  loopback, local output, and packet-originated output. RAW sockets retain the
  complete L2 frame; DGRAM sockets remove complete VLAN/QinQ L2 headers and
  expose the inner protocol. Linux skb header identity survives pull and head
  expansion. Sender suppression applies only to its outgoing frame, while a
  later loopback HOST delivery remains visible. Deterministic tests cover all
  packet types, namespace/device identity, BPF drop/truncation, malformed raw
  frames, exact-once delivery, VLAN/QinQ, stale generations, and generated
  neighbor control traffic. Final gates passed: hosted net 764/764, Linux
  netdev 13/13, Virtio net 27/27, socket 33/33, and syscalls 99/99; workspace
  check and x86_64/aarch64 kernel builds passed.
- [x] **N06 packet memberships and device lifecycle**.
  Implement Linux packet memberships including promiscuous/all-multicast,
  interface move/removal behavior, namespace teardown, and close races.
  Claimed by `B873-network-packet-memberships` on 2026-07-15 from merge
  `ff04b77f3`. Implementation owns `PACKET_ADD_MEMBERSHIP` and
  `PACKET_DROP_MEMBERSHIP` in the socket/device layers under RTNL with exact
  socket-local duplicate counts and device-wide references for multicast,
  promiscuous, all-multicast, and unicast memberships. Administrative and
  packet-derived receive modes share one canonical filter state. Linux module
  drivers receive flags plus stable multicast/unicast lists through
  `ndo_set_rx_mode`. Final file release, unregister, namespace move, and
  admitted-add/close races flush exact device generations; bound sockets detach
  with `ENETDOWN`. Local evidence: hosted net 770/770, syscalls 103/103,
  socket 33/33, Virtio net 27/27, Linux netdev 14/14, workspace check,
  host/x86_64/aarch64 KPI header smokes, x86_64/aarch64 kernel builds, and
  diff/file-cap checks. Full modules remains at its unrelated baseline
  debugfs-automount fixture failure (187/188). Merged in PR #3153 at
  `490c315b7`.
- [~] **N07 packet options and scalable receive**.
  Audit and implement required `SOL_PACKET` options, statistics, fanout, and
  mmap ring contracts. Split each independently testable contract into its own
  numbered bug branch when implementation begins. Claimed by
  `B874-network-packet-options` on 2026-07-15 from merge `490c315b7`.
  Audit result: only membership options exist. `getsockopt(SOL_PACKET, ...)`,
  all active scalar/data-path options, statistics, fanout, RX/TX rings, and
  packet-fd mmap are absent. Ordinary inode mmap fallback cannot represent
  packet-ring shared frames or mapped-ring lifetime. Implement in the order
  below; an option does not land as inert stored state before its observable
  Linux behavior exists.
  - [x] N07.1 canonical packet-option ABI and immediate receive controls.
    Move `SOL_PACKET` UAPI into one shared owner; add packet-only type checks,
    strict Linux optlen/usercopy/error ordering, getsockopt value-result
    copyout, `PACKET_IGNORE_OUTGOING`, and explicit `ENOPROTOOPT` evidence for
    obsolete `PACKET_RECV_OUTPUT` and unsupported `PACKET_TX_TIMESTAMP`.
    Claimed by `B875-network-packet-option-abi` on 2026-07-15 from merge
    `fed783485`. One socket-owned atomic option now controls outgoing
    observation at the canonical delivery boundary without suppressing later
    loopback HOST ingress. Shared `net::uapi` numbers drive set/get dispatch;
    exact native-int parsing, packet-only checks, value-result get lengths,
    failure length preservation, and explicit unsupported defaults match the
    Linux packet protocol boundary. Local gates: hosted net 771/771, syscalls
    106/106, workspace check, x86_64/aarch64 kernel builds, diff/file caps,
    and B875-owned spec-lint checks pass. Full spec-lint retains 1,987 unrelated
    baseline findings. Merged in PR #3155 at `537554cd9`.
  - [x] N07.2 packet receive metadata controls.
    Implement `PACKET_AUXDATA` ancillary delivery and `PACKET_ORIGDEV` using
    retained original-device identity, including VLAN status/TCI/TPID,
    checksum status, snaplen/full-length, L2/L3 offsets, truncation, cmsg
    truncation, namespace/device-generation, and recvfrom/recvmsg parity.
    Claimed by `B876-network-packet-metadata` on 2026-07-15 from merge
    `537554cd9`. One canonical receive record now retains enqueue-time
    sockaddr_ll and auxdata state through BPF capture truncation and later
    user-buffer truncation. `PACKET_ORIGDEV` selects the retained original
    generation at enqueue; cross-namespace originals are rejected.
    `PACKET_AUXDATA` emits native 20-byte ancillary data with Linux checksum,
    TCP GSO, VLAN, full/snapshot length, and L2/L3 offset semantics. Virtio
    and Linux-module RX translate driver checksum/offload state at the netdev
    boundary. Local gates: hosted net 774/774, syscalls 107/107, Virtio net
    28/28, focused Linux netdev 5/5, workspace check, x86_64/aarch64 kernel
    builds, and diff/file caps pass. Full modules retains its unrelated
    debugfs automount baseline failure (178/179). Full lint reports 1,989
    findings versus 1,990 on `main`; B876-added code is clean. Merged in PR
    #3156 at `335ba6da1`.
  - [x] N07.3 packet statistics and queue pressure.
    Replace fixed frame-count admission with byte-accounted receive pressure;
    count packets/drops at Linux admission points and implement destructive
    `PACKET_STATISTICS` V1/V2 and V3 readback with atomic read-reset behavior.
    Claimed by `B877-network-packet-statistics` on 2026-07-15 from merge
    `335ba6da1`. One socket-owned queue now owns frames, byte charge, pressure,
    admitted-packet count, and drops; no parallel frame-count limit remains.
    Positive-filter frames use Linux-style prospective receive-buffer
    admission, dequeue clears byte pressure, and `PACKET_STATISTICS` clears
    counters before copyout. Exact `PACKET_VERSION` set/get selects native
    8-byte V1/V2 or 12-byte V3 statistics, with V3 freeze count reserved for
    the later ring owner. Local gates: hosted net 776/776, syscalls 109/109,
    workspace check, x86_64/aarch64 kernel builds, diff/file caps pass. Full
    lint retains 1,989 unrelated baseline findings. Merged in PR #3157 at
    `80493b29d`.
  - [x] N07.4 namespace-scoped packet fanout.
    Implement `PACKET_FANOUT` legacy and `fanout_args` ABIs, HASH/LB/CPU/RND/QM/
    ROLLOVER/CBPF/EBPF modes, flags, unique IDs, member compatibility/capacity,
    `PACKET_FANOUT_DATA`, close/unbind races, group filter ownership,
    `PACKET_ROLLOVER_STATS`, and exactly-one receive selection.
    Claimed by `B878-network-packet-fanout` on 2026-07-15 from merge
    `80493b29d`. One namespace-keyed group owner implements legacy and native
    fanout ABIs, exact member compatibility/capacity, unique IDs, all eight
    Linux selection modes, group-owned CBPF/EBPF, rollover pressure/history
    and statistics, outgoing suppression, IPv4 defragmentation, and final
    release. Receive selection serializes with membership removal and binds;
    queue mapping is retained from Linux NAPI and Virtio RX metadata. Tests
    prove exactly-one delivery, namespace isolation, selection modes, capacity,
    filters, rollover, defragmentation, bind rejection, and close selection.
    Local gates: hosted net 786/786, syscalls 111/111, Virtio net 28/28,
    focused Linux netdev 5/5, workspace check, x86_64/aarch64 kernel builds,
    and diff/file caps pass.
  - [x] N07.5 packet-ring shared-memory foundation.
    Add socket-owned page-backed RX/TX ring objects, V1/V2/V3 request parsing
    and overflow/alignment validation, consume the established
    `PACKET_VERSION`, and add `PACKET_HDRLEN`/`PACKET_RESERVE`; route packet-fd
    `MAP_SHARED` through a dedicated backing
    with zero-offset/exact-size checks, fork/unmap pins, mapped-ring `EBUSY`,
    and final-file-release cleanup. Claimed by
    `B879-network-packet-ring-foundation` on 2026-07-16 from merge
    `5ca8dea05`. One socket-owned RX/TX ring owner allocates zeroed page-backed
    blocks, retains exact V1/V2/V3 layout state, and releases object references
    only after socket and VMA pins disappear. Native `tpacket_req`/`req3`
    import, page/frame/private-area/count overflow validation, exact
    `PACKET_VERSION` transactions, `PACKET_HDRLEN`, and `PACKET_RESERVE` match
    Linux ordering. Packet-fd mmap inserts owner frames for Linux shared or
    private mapping types with zero-offset/exact combined RX-then-TX size; one
    dedicated backing retains frames across close, fork, and VMA splits and
    blocks ring changes until its last clone drops.
    Deterministic tests cover versions, malformed layouts, reserve/header
    minima, busy precedence, combined ordering, mmap shape, final close, and
    backing-clone lifetime, and private direct-frame fork/COW behavior. Local
    gates: hosted net 794/794, syscalls 114/114, VMM 153/153, workspace check,
    x86_64/aarch64 kernel builds, and diff/file caps pass. Merged in PR #3159
    at `baa76c16c`.
  - [x] N07.6 TPACKET V1/V2 receive rings.
    Publish frames with exact status ownership transitions, sockaddr_ll,
    offsets, timestamps, VLAN/checksum metadata, snaplen/full length, poll,
    wake, wrap, pressure/drop accounting, and concurrent userspace release.
    Claimed by `B880-network-tpacket-v12-rx` on 2026-07-16 from merge
    `baa76c16c`. One canonical ring-or-queue delivery transaction serializes
    against ring installation and publishes V1/V2 frames with Linux's native
    headers, aligned raw/datagram offsets, sockaddr_ll, realtime timestamps,
    snaplen/full length, checksum/GSO/V2 VLAN metadata, and status-last release
    ownership. Page-aligned hosted backing exercises the same mapped bytes as
    kernel HHDM storage. Atomic userspace status release drives wrap/reuse;
    quarter-ring fanout room, previous-frame poll readiness, wake-on-drop,
    clear-on-read LOSING, and packet/drop statistics match `tpacket_rcv`.
    Deterministic tests cover native layouts, clamp/offset calculations,
    metadata, timestamps, canonical non-duplicated delivery, pressure states,
    full-ring drops, statistics, wrap, release, and V1 VLAN suppression. Local
    gates: hosted net 800/800, workspace check, x86_64/aarch64 kernel builds,
    and diff/file caps pass. PR #3160.
  - [x] N07.7 TPACKET V3 receive blocks.
    Native V3 block descriptors preserve private bytes, chain aligned packets,
    expose RXHASH/VLAN metadata, and publish status last. Exact-boundary block
    retirement, configurable/default timeout retirement, ownership freeze/thaw,
    destructive drop/freeze statistics, quarter-block fanout pressure, previous-
    block poll readiness, and final-close timer serialization match Linux.
    Deterministic tests cover layouts, chaining, timeout, release/reuse, sticky
    private data, metadata, pressure, statistics, and mmap-pinned teardown.
    Local gates: hosted net 810/810, workspace check, x86_64/aarch64 kernel
    builds, diff lint, and file caps pass. PR #3161.
  - [x] N07.8 packet transmit rings.
    V1/V2/V3 fixed-slot parsing, volatile mapped-byte snapshots, atomic send-
    request ownership, sending/available/wrong-format transitions, wrap, partial
    progress, and `PACKET_LOSS` match Linux TX-ring behavior. One canonical net
    transmit owner handles ordinary and ring packet sends; write, sendto,
    sendmsg, and sendmmsg kicks avoid importing ignored payload bytes. One exact
    namespace/device-generation lease spans each batch, explicit sockaddr_ll
    fields retain Linux validation and literal protocol semantics, and close,
    concurrent kick, poll-generation, retry, mmap, and final-file lifetime races
    have deterministic coverage. Claimed by `B882-network-packet-tx-rings` on
    2026-07-16 from merge `05679b5d7`. Local gates: hosted net 823/823, socket
    35/35, syscalls 116/116 plus integration suites, workspace check,
    x86_64/aarch64 kernel builds, diff lint, touched-code lint, and file caps.
    PR #3162.
  - [x] N07.9 packet offload and transmit policy options.
    Candidate implements `PACKET_VNET_HDR`, `PACKET_VNET_HDR_SZ`,
    `PACKET_TIMESTAMP`, `PACKET_TX_HAS_OFF`, `PACKET_COPY_THRESH`, and
    `PACKET_QDISC_BYPASS` with socket-owned state, ring ordering, V1/V2 copy
    fallback, receive VNET layouts, all-version TX offsets, software checksum
    and TCPv4 GSO, tested UDP/IPv6 fallback paths, qdisc queued/direct dispatch,
    FIFO backpressure, IRQ/BH-safe hardware serialization, and tap visibility.
    Direct syscall/uaccess, readiness, hardware timestamp, remaining offload
    combinations, and Linux differential evidence remain N07.10 scope.
    Claimed by `B883-network-packet-offload-options` on 2026-07-16 from merge
    `a6917a573`. Local gates: hosted net 853/853, virtio-net driver 28/28,
    socket 35/35, syscalls 120/120 plus integration suites, workspace check,
    x86_64/aarch64 kernel builds, diff check, and touched-file caps. PR #3163,
    merge `344788a56`.
  - [~] N07.10 Linux differential and integrated completion gate.
    Run matching glibc C probes on Linux and Oxide for every set/get option,
    malformed layout, ring version, mmap shape, fanout mode, queue-pressure,
    close/race, and poll transition; then run full network/syscall/VMM/VFS,
    dual-architecture builds, and the campaign dual smoke.
    Claimed by `B884-network-packet-linux-differential` on 2026-07-16 from
    merge `4dd368cbf`.
    - [x] N07.10.1 Add one portable GNU/glibc probe, GNU cross-build/rootfs
      injection, root execution, retained UART evidence, and exact ordered
      Linux/Oxide comparison for x86_64 and aarch64. The 79-record Linux
      oracle is byte-stable across three consecutive runs. First x86 Oxide
      execution completed and exposed exact differences rather than timing
      out behind the unrelated late-boot failure.
    - [x] N07.10.2 Fix packet `getsockopt` output-length/value ordering and
      unsupported-option precedence. Linux preserves `optval` when `optlen`
      is read-only and returns `ENOPROTOOPT` for an unknown option without
      touching either output. One common post-dispatch transaction now clamps
      the value, writes `optlen` before `optval`, preserves statistics-reset
      side effects, and leaves unsupported-option outputs untouched. The x86
      differential removes all three getsockopt mismatches; only N07.10.8 ring
      records remain. Hosted syscalls 121/121 and x86_64/aarch64 kernel builds
      pass.
      Claimed by `B885-network-packet-get-copy-order` on 2026-07-16 from
      merge `eb5efef94`. PR #3166, merge `ba25e43f3`.
    - [x] N07.10.3 Verify V3 private-offset width. The queued widening was a
      false finding: Linux 6.19 validates the `u32` request, then stores it in
      `tpacket_kbdq_core.blk_sizeof_priv` as `unsigned short`. Host Linux
      accepts `tp_sizeof_priv=65536` and reports both private and first-packet
      offsets as 48, exactly matching Oxide. Hosted and GNU/glibc differential
      regressions now lock this Linux behavior; no kernel change is required.
      Hosted net passes 854/854, both GNU targets compile, and the x86 80-record
      differential leaves only the existing N07.10.8 ring differences.
      Claimed by `B887-network-packet-v3-private-offset` on 2026-07-16 from
      merge `ba25e43f3`. PR #3168, merge `358d74c74`.
    - [x] N07.10.4 Fix packet-origin fanout loop suppression, member-local
      ignore-outgoing interaction, and Linux swap-delete member ordering.
      Packet-origin output now suppresses its complete fanout group before
      selection while ordinary sockets suppress only the origin. Fanout
      delivery applies `PACKET_FANOUT_FLAG_IGNORE_OUTGOING` at the group hook,
      not member-local `PACKET_IGNORE_OUTGOING`. Final release uses Linux
      swap-delete ordering; packet-ring replacement temporarily unlinks and
      appends the running member under one lock order and rejected changes
      preserve member order. Hosted fanout
      tests cover LB, CPU, QM, CBPF, EBPF, close order, BPF retention, ring
      replacement, group suppression, and ordinary observation. The four new
      GNU/glibc records match host Linux exactly in the x86 84-record
      differential; only N07.10.8 ring records differ. Hosted net passes
      860/860 and both kernel targets build.
      Claimed by `B894-network-packet-fanout-semantics` on 2026-07-16 from
      merge `6979cecc2`. PR #3182, merge `98f7b66bf`.
    - [x] N07.10.5 Fix TX-ring poll semantics. AF_PACKET now preserves
      generic datagram writability while the current TX frame is available,
      `SEND_REQUEST`, `SENDING`, or `WRONG_FORMAT`; TX status wakes are keyed
      to `POLL_OUT` and do not wake read-only subscribers. The GNU/glibc probe
      obtains `WRONG_FORMAT` through a malformed kernel kick, repairs the
      header, and completes the same frame. Its complete TX record matches
      host Linux exactly in the x86 84-record differential; only the three
      N07.10.8 RX-ring records differ. Focused TX tests pass 11/11, full net
      passes 860/860, both GNU targets compile, and both kernel targets build.
      Claimed by `B903-network-packet-tx-poll` on 2026-07-16 from merge
      `a26dc6040`. PR #3205.
    - [x] N07.10.6 Replace approximate queue charging with Linux-equivalent
      skb truesize accounting and compare the exact first-drop transition.
      Ordinary and copy-fallback queues retain allocation-class charge, admit
      Linux's crossing frame, and reject the next frame when current rmem has
      reached the receive budget. Fanout rollover consumes the same prospective
      charge as final admission. Hosted tests cover exact 64-bit linear/paged
      allocation classes, crossing admission, release, pressure, and destructive
      statistics. The GNU/glibc probe matches Linux exactly at effective
      `SO_RCVBUF=4096`: five 64-byte frames are accepted and the sixth drops.
      Full net passes 861/861, both GNU targets compile, both kernel targets
      build, and the x86 85-record differential differs only in the three
      existing N07.10.8 RX-ring records.
      Claimed by `B925-network-packet-queue-truesize` on 2026-07-16 from
      merge `88c36cf37`.
    - [x] N07.10.7 Carry production raw-hardware timestamps through receive
      ingress, then verify all receive ring versions. Linux-netdev skb software
      and raw-hardware timestamps now reach canonical packet metadata; AF_PACKET
      selects hardware, software, or unlabelled realtime fallback with Linux
      status-bit precedence. The virtio-net 1.2 receive header has no timestamp
      field, so that driver correctly reports no hardware source instead of
      manufacturing one. GNU/glibc V1/V2/V3 raw-hardware-without-source records
      match host Linux byte-for-byte in the x86 88-record differential. Hosted
      modules pass 14/14, full net passes 861/861, virtio metadata passes 1/1,
      both GNU targets compile, and both kernel targets build. The only three
      differential differences remain owned by N07.10.8.
      Claimed by `B943-network-packet-hw-timestamps` on 2026-07-16 from
      merge `1c6c8b5eb`.
    - [x] N07.10.8 Fix packet-loopback classification and duplicate V3
      publication. Packet buffers retain a canonical MAC-header marker;
      loopback raw transmit publishes one synchronous receive view classified
      against the device broadcast address while preserving the queued L3 view.
      Linux's outgoing `ptype_all` rule now rejects protocol-bound sockets and
      fanout groups before selector mutation. Protocol-bound V1/V2/V3 rings
      report multicast packet type 2 and one V3 publication; `ETH_P_ALL` keeps
      the distinct outgoing and receive taps. Full net passes 863/863, both
      kernel targets build, and all 88 x86 GNU/glibc differential records match
      host Linux byte-for-byte.
      Claimed by `B948-network-packet-loopback-v3` on 2026-07-16 from
      merge `61ae3bdd2`.
    - [x] N07.10.9 Extend differential cases for GSO combinations, TX-ring
      readiness states, fanout close races, partial unmap/remap/fork, and
      close while blocked; run integrated hosted and dual-architecture gates.
      The 95-record GNU/glibc probe covers the complete VNET/GSO matrix,
      direct epoll TX states, V3 retire timeout, concurrent fanout close,
      split/unmap/fork/mremap lifetime, and controlled blocked-receive close.
      Linux and Oxide match byte-for-byte on x86_64 and aarch64; full net
      passes 863/863 and both GNU targets compile with native glibc loaders.
      Claimed by `B965-network-packet-race-matrix` on 2026-07-16 from merge
      `77a96422c`.
    - [~] N07.10.10 Clear the campaign dual-smoke blocker. B886 found two
      independent Linux contract defects. `unshare(CLONE_FILES)` now publishes
      a private fd-table snapshot, with a deterministic ownership regression.
      The D-Bus startup failure itself came from missing unqualified constants
      in `getsockopt(SOL_SOCKET, *)`: Rust treated `SO_TYPE`, `SO_ACCEPTCONN`,
      `SO_DOMAIN`, and `SO_PROTOCOL` as catch-all pattern bindings, making later
      arms unreachable. Canonical `net::uapi` patterns restore option dispatch;
      a focused hosted regression passes and x86 reaches `basic.target` with
      no broker or launcher failure. ARM also exposed lockstep
      blockers: process-context signal delivery did not kick an
      already-runnable remote target, GICv3 SGI/PPI interrupts were not assigned
      to enabled Group 1, and CNTV periodic/one-shot mode was shared globally
      instead of owned per CPU. `B886-dbus-socket-fd-lifetime` adds the remote
      reschedule path, explicit private-interrupt grouping, per-CPU timer mode,
      BSP-only global deadline rearming, and timeout per-CPU heartbeat capture.
      Hosted sched passes 173/173, hal-aarch64 passes 47/47, focused syscall,
      devpts, IPC, arch-irq, namespace ownership 13/13, and fd-table ownership
      3/3 checks pass. Prior integrated ARM smoke reached `basic.target` in
      128s; final clean ARM verification after the socket-option fix remains.

## C. Message I/O Completion

- [ ] **N08 recvfrom row 45**.
  Complete fd/pointer/length/flag errno ordering, copy-fault side effects,
  every supported family, OOB/error-queue interaction, security hooks, and
  syscall-context differential tests.
- [ ] **N09 sendmsg row 46**.
  Complete IP/IPv6 control-message effects, VSOCK destination behavior,
  security hooks, fault ordering, and differential tests. B854 introduces the
  canonical socket work layer above net, netlink, VFS, and sched and moves send
  target classification, wait policy, SCM effects, and SIGPIPE completion out
  of syscall slots 44/46; each ABI shim now imports and calls one work function.
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
  B854 puts batching, lazy per-entry import/copyout, `MSG_BATCH`, partial-stop,
  and retained `SendFile` policy in the N09 socket work layer; the row-307 shim
  owns no protocol dispatch and does not pre-import the complete batch.
- [ ] **N24 network ioctl row 16**.
  Complete socket and interface ioctl command coverage, mutable interface
  properties, namespace/device ownership, capability and security checks,
  uaccess/error ordering, compat ABI, and differential tests.
- [ ] **N25 TCP blocking-wait linearization**.
  Arm and recheck connect/write wait conditions without SYN-ACK, RST, ACK,
  close, timeout, or signal lost-wakeup windows; split the over-cap wait module.
- [~] **N26 VSOCK Linux lifecycle and blocking linearization**. B854 owns the
  atomic-connect, failed-connect, typed-bind, readiness-notification, SIGPIPE,
  and shutdown/wait-arm portions in PR #3133; socket-option
  coverage remains.
  - [x] N26.1 move connect into one socket-owned atomic state machine; publish
    `Connecting` before transport/table work so concurrent connects cannot both
    observe `Init` or orphan a live connection record.
  - [x] N26.2 connect connection/listener state transitions to socket poll
    subscribers; publish RX, response, credit, shutdown, reset, and accept-backlog
    readiness and set/consume `SO_ERROR` for failed connects. B854 installs one
    inode-owned subscriber source, publishes RX, credit, shutdown, reset, close,
    and accept-backlog transitions, and completes RST, timeout, and driver-removal
    failures through consumable `SO_ERROR` plus `POLL_ERR | POLL_OUT`.
  - [x] N26.3 move typed bind validation and transition into `VsockSocket`;
    validate sockaddr length/family and reject rebinding a live listener or
    connection without replacing its canonical table record. B854 moves the
    typed transition behind the socket owner and covers live-state rejection.
  - [ ] N26.4 implement Linux VSOCK socket-option coverage instead of blanket
    `ENOPROTOOPT`, with canonical state and exact optlen/error ordering.
  - [x] N26.5 emit `SIGPIPE` on VSOCK `EPIPE` write paths unless suppressed by
    `MSG_NOSIGNAL`, matching the shared socket send contract. B854 routes write,
    writev, sendto, and sendmsg through the shared completion contract.
  - [x] N26.6 serialize receive terminal state and send credit/close publication
    against wait arming; prove retry-to-park transitions cannot lose a final wake.
    B854 adds locked shutdown latches, retry/arm/recheck gates, Linux shutdown
    readiness, and deterministic blocked-reader/writer schedules.
  - [x] N26.7 serialize every hosted test touching the global VSOCK driver
    registry and connection table through one canonical test lock. Parallel
    suites must not uninstall another test's transport or poison unrelated tests.
    B856, PR #3135, merge `fa49538a`, covered the root VSOCK test modules but
    not every lifecycle/interleaving participant. Full-net 32-thread stress
    still produced eight cross-test driver/table failures and poisoned locks.
    B862, PR #3141, commits `807f4b697`, `a0801712a`, `790dfa730`, and
    `f6d3bcf5a`, replaces raw guards with one
    poison-recovering RAII domain that resets endpoints, primary ownership,
    connections, listeners/backlogs, bindings, ephemeral allocation, and
    tail-credit injection on entry and drop. Virtio VSOCK tests compose context,
    softirq handler/pending-bit, protocol endpoint, and owned-frame cleanup.
    Deterministic complete-reset, invisible quiesced-endpoint unwind, and driver
    cleanup regressions passed; net VSOCK 95/95 and driver 13/13 passed at 32
    threads, both stress gates passed 50/50, full net passed 738/738 at 32
    threads, and x86_64/aarch64 kernel builds passed. Intermediate smoke skipped
    under the standing user authorization.
- [ ] **N27 NETLINK pending-error receive parity**.
  Route read, recvfrom, and recvmsg through one queue/error decision so queued
  datagrams precede pending errors and empty blocking readers wake on errors.
- [x] **N28 hosted network fixture isolation**.
  Prove the full hosted net suite remains deterministic under parallel execution
  without serializing unrelated production ownership domains.
  - [x] N28.1 give each IPv4 forwarding test a private network namespace,
    namespace-owned interfaces, routes, and forwarding sysctl state.
    B857, PR #3136; six 32-thread targeted schedules passed 3/3 and the full
    sequential net suite passed 719/719. B858, PR #3137, commit `8842bd46`,
    claims, destroys, and finishes every hosted namespace through a canonical
    lifetime-locked RAII fixture. Direct registry, `NET_NS`, and subsystem-state
    absence assertions passed 25 consecutive 32-thread runs; full net passed
    719/719; x86_64 and aarch64 target checks passed.
  - [x] N28.2 isolate AF_UNIX SCM-GC graph fixtures across parallel collection
    schedules without weakening production collection concurrency. B859, PR
    #3138, commit `e6a179ed`, routes all 81 AF_UNIX tests plus six namespace
    and four socket-inode participants through one poison-recovering hosted
    domain. Explicit collector reservation proves a concurrent pending request
    runs a second pass, and RAII cleanup cannot strand collector ownership.
    AF_UNIX passed 81/81 at 32 threads and 50 consecutive parallel runs; all
    deterministic collector schedules passed 100 consecutive runs; full
    sequential net passed 723/723;
    x86_64 and aarch64 kernel builds passed. Intermediate smoke skipped under
    the standing user authorization.
    - [x] N28.2a make the stale-running observer handoff RAII-released so a
      timeout or assertion unwind cannot leave its requester spinning after
      the owning test exits. B861 commits `366a252ca`, `faf428a23`, and
      `b432f7185` give every observer exact shared state and publish release
      through RAII; observers cannot release or satisfy one another. Deterministic unwind and overlapping
      regressions are included in the 100/100 SCM and 50/50 AF_UNIX gates.
  - [x] N28.3 isolate hosted local-stack interface/address and control-event
    fixtures. Independent `NetStack` instances reuse namespace-0 interface IDs
    while `IPV4_ADDRS` and control-event hooks are process-global; use private
    namespace RAII fixtures where semantics permit and one canonical initial-
    network-domain lock only where tests require namespace 0/global hooks.
    Full-net 32-thread stress exposed `f180c_ns_for_unowned_addr_silent` and
    `connected_raw4_publishes_hard_not_soft_matching_errors` losing
    `(net_ns=0, iface=1)` during concurrent teardown. B860, PR #3139, commits
    `7c7f0ead` and `374d02f9`, adds one poison-recovering initial-domain owner
    that restores namespace-0 rows and scoped notifier/netfilter callbacks
    while preserving private-namespace state. Every direct local-stack/address
    participant and netlink notifier participant retains that owner. Full net
    excluding separately tracked VSOCK tests passed 25 consecutive 32-thread
    runs; the original NDP and raw4 collision families passed 100 consecutive
    runs each; netlink passed 50 consecutive 32-thread runs (101/101 each);
    full sequential net passed 727/727; x86_64 and aarch64 builds passed.

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
