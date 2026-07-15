# state - network completion

Update: 2026-07-15.

## Current lane

- `main`: `86c7b35e`, synchronized with `origin/main` after D230 merged.
- B852 atomic socket and accepted-fd CLOEXEC publication merged in PR #3130 at
  `40d0cf56`; B853 VSOCK final-file cleanup implementation and verification are
  complete on `B853-vsock-final-file-release`; merge pending.
- N01-N02, N03.1-N03.8.2, N03.8.6, and N03.8.7 are merged.
- N03.7 final-drop teardown merged in PR #3107 at `71457583`.
- N03.8.1 lifecycle and teardown race proof merged in PR #3109 at `7d6c2abb`.
- N03.8.2 physical ingress owner lease merged in PR #3111 at `f8d5c20a`.
- N03.8.6 namespace-aware Virtio uninstall merged in PR #3113 at `8c077249`.
- N03.8.7 control-plane/lifecycle serialization merged in PR #3115 at
  `11b75c13`.
- N02.1 multicast work-function ownership and unbound membership proof merged
  in PR #3117 at `9a076593`.
- N01.19 raw bind and `SO_BINDTODEVICE` serialization merged in PR #3119 at
  `61bc95f6`.
- N01.20 ICMPv4 fragmentation-needed and protocol PMTU/error semantics merged
  in PR #3121 at `b5195a57`.
- N03.8.3 private-loopback namespace owner retention merged in PR #3123 at
  `603c32bc`.
- N03.8.4 atomic `SIOCGSKNS` fd publication merged in PR #3125 at `ab29967e`.
- N03.8.5a materialization/final-drop schedules merged in PR #3127 at
  `5b249311`.
- N03.8.5b.i concrete TCP transport ownership and passive-child teardown merged
  in PR #3129 at `d83ffe82`.

## Implemented

- Concrete network namespace owners are retained by tasks, namespace fds,
  INET/UNIX/PACKET/NETLINK/VSOCK sockets, and accepted sockets.
- Final owner drop signals a process-context reaper exactly once.
- Teardown quiesces interfaces before removing address, neighbor, multicast,
  fragment, route/rule, transport, UNIX, sysctl, and registry state.
- Dead or claimed numeric namespace IDs cannot recreate canonical state.
- Persistent devices are retired and returned to the initial namespace;
  namespace-owned virtual devices are destroyed.
- Callback/registry/reaper transitions share production logic with Loom models.
- Reaper notification uses monotonic publication/consumption generations; harvest
  cannot erase a concurrent final-drop notification before park.
- Physical RX holds a concrete namespace-owner generation lease across AF_PACKET
  and L3 delivery; Virtio drops old descriptor completions after reassignment.
- Physical uninstall follows the canonical current namespace generation and
  cannot free Virtio queues/runtime before interface unpublication completes.
- Resume-pending generations admit RX before `NetRx` wakeup but reject uninstall
  claims until device resume completes.
- Per-stack RTNL and exact interface-generation leases serialize link, address,
  route, rule, multicast, RA/DAD, notification, and driver-effect work against
  move, unregister, teardown, and ifindex reuse.
- Canonical route/rule/address state implements true ECMP aliases, deletable
  built-in rules, IPv4 peer addresses, exact netlink selectors, and Linux ioctl
  errors without shadow registries.
- ICMPv4 fragmentation-needed handling uses output-route keyed PMTU state and
  per-socket discovery modes across UDP, raw, and TCP; TCP validates quoted
  sequence state and retransmits with reduced MSS without closing the socket.
- Private-loopback drain snapshots retain the concrete namespace owner until
  all snapshotted packets finish protocol dispatch.
- `SIOCGSKNS` reserves `FD_CLOEXEC` before publishing its namespace file, with
  no post-publication flagging or reusable-slot error window.
- Namespace-state materialization is ordered against final owner drop: a
  successful registry lookup pins the owner through publication, while a
  teardown-claimed ID cannot publish or reconstruct state.
- TCP bind and transport entries retain concrete namespace owners. Listener
  close rejects late passive children, reaps half-open and completed-unaccepted
  children, preserves accepted children, and uses identity-safe rollback for
  duplicate tuples, stale work, timers, and transmit failure.
- `socket(2)`, ordinary `accept`/`accept4`, VSOCK `accept4`, and io_uring accept
  publish the file and `FD_CLOEXEC` descriptor flag in one fd-table critical
  section; socketpair retains its existing two-fd atomic reservation path.
- VSOCK final open-file-description release removes the exact listener or
  connection once, drains only that listener's pending children, preserves
  accepted children and replacement tuples, and linearizes inbound publication
  against listener removal.
- Every VSOCK syscall path retains the resolved `File` through the operation;
  close/reuse cannot release or replace the endpoint under blocking connect,
  accept, receive, send, bind, listen, or ordinary read.

## Verification

- Loom runner: net 525 and network-namespace 6; zero failures.
- Hosted: net 598, netlink 89, syscalls 53, Virtio net 25,
  network-namespace 3, netdev modules 4; zero failures.
- B847 hosted: net 641, syscalls 59, procfs 47; zero failures. x86 and ARM
  custom-target checks passed.
- B848 hosted net 642 and x86/ARM custom-target checks passed.
- B849 hosted syscalls 62, VFS reservation 5, and x86/ARM custom-target checks
  passed.
- B850 hosted net 643 and x86/ARM custom-target checks passed; deterministic
  lookup-first and claim-first schedules use production registry/state paths.
- B851 hosted net 651 and x86/ARM custom-target checks passed; eight focused
  passive-child tests cover close, accept transfer, duplicate SYN/final ACK,
  stale tuple cleanup, transmit rollback, and final namespace-owner release.
- B852 hosted syscalls 70, including socket-fd publication/exec races, io_uring
  accept operand mapping, and existing socketpair publication tests; x86/ARM
  custom-target checks passed.
- B853 hosted net 665 and syscalls 72; 48 focused VSOCK tests cover duplicate
  and final fput, failed fd publication, exact-record reuse, duplicate tuples,
  close idempotence, late RX, wildcard conflicts, terminal-frame ordering, and
  publication/removal races. Hosted File-pin tests and x86/ARM custom-target
  checks passed; changed-file code lint is clean.
- `make x86` and `make arm` passed.
- N03.7 smoke reached `basic.target`: x86 70s, ARM 129s.
- `git diff --check`, length lint, and changed-file code lint passed.

## Remaining network work

- N03.8.5b.iv-N03.8.5h retained-owner schedule matrix. B854 owns cross-family
  File/FdTable close and active-syscall schedules after B852 atomic publication
  and B853 complete VSOCK final-fput/file-pin semantics.
- N04-N24 and the completion gate in `scratch/network-plan.md`.
- Correct stale syscall matrix evidence/status while executing the owning lanes.

## First resume command

`cd /home/nd/oxide/kernel && git pull --ff-only && rg -n 'N03.8' scratch/network-plan.md`
