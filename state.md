# state - network completion

Update: 2026-07-15.

## Current lane

- Active branch: `B871-network-common-socket-filter`, created from current
  `origin/main` merge `868998ed0` after B870 merged in PR #3150.
- N04 owns common socket-filter attach/detach/lock, receive filtering,
  truncation/drop, and accepted-socket inheritance across AF_UNIX, AF_NETLINK,
  and AF_VSOCK.
- B870 N03.8.5h composed owner-retention Loom matrix merged in PR #3150 at
  `868998ed0`; N03 and every child row are complete.
- B867 merged in PR #3147 at `46dd23b5f`. B865 merged in PR #3144 and B866
  merged in PR #3145.
- B852 atomic socket and accepted-fd CLOEXEC publication merged in PR #3130 at
  `40d0cf56`. B853 VSOCK final-fput, exact endpoint identity, transport ordering,
  and syscall File pins merged in PR #3132 at `6e4e4123`. B854 cross-family
  socket File/FdTable schedules merged in PR #3133 at `1d4e3ef4`. B855 SCM
  receive publication and final-release collection merged in PR #3134 at
  `84d0a1fd`. B856 VSOCK hosted-test serialization merged in PR #3135 at
  `fa49538a`. B857-B860 close forwarding, VSOCK, AF_UNIX, and initial-network-
  domain fixture isolation in PRs #3136-#3139. B861 SCM final-release collection
  merged in PR #3140, B862 VSOCK hosted isolation merged in PR #3141, and B863
  namespace-fd setns close/reuse merged in PR #3142 at `00e9b521b`.
- B864 `pidfd` canonical identity/thread-group lifetime refactor merged in PR
  #3143 at `55fe2f117`.
  Scheduler 149/149, pidfd 6/6, VFS fd-table 5/5, syscalls 88/88, both 50-run stress gates,
  changed-owner lint, length lint, and x86_64/aarch64 builds passed.
- B865 N03.8.5e.ii concrete non-network namespace ownership merged in PR
  #3144 at `5eacb0e8e`.
  Canonical cgroup, IPC, PID, time, user, UTS, and mount owners; weak live
  indexes; exact task/nsfd retention; exit-before-Zombie release; owner-retaining
  mount transactions; and detached-tree cross-namespace rebinding are committed.
  Hosted, stress, and x86_64/aarch64 build gates pass. The x86 smoke rerun
  reached `basic.target`.
- B867 N03.8.5e.iv canonical active namespace trees and native TIME semantics
  are implemented. One eight-kind monotonic registry owns global/per-kind/
  direct-owner indexes; active references and lifetime pins have distinct
  semantics; listns handles Linux filtering, pagination, extension validation,
  and per-element faults without task or inode discovery.
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
- Namespace registry teardown claims require explicit final-destructor
  publication; unrelated notifications cannot claim an owner whose destructor
  is still dropping canonical fields.
- Physical RX holds a concrete namespace-owner generation lease across AF_PACKET
  and L3 delivery; Virtio drops old descriptor completions after reassignment.
- Virtio RX runtime and ring consumption require the exact registered device Arc
  plus generation, so device-key reuse with an equal numeric generation cannot
  consume a replacement ring.
- Linux NAPI and skb receive paths stamp the admitted interface generation,
  reject work after retirement, and publish NAPI generation/state transactionally
  across concurrent prepare and disable.
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
- Loopback retirement atomically closes admission and purges queued packets;
  drains acquire the exact generation lease before the first dequeue and account
  both purge drops and protocol delivery errors.
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
- Socket I/O and control routes resolve one open file description and retain it
  through classification, status-flag reads, protocol dispatch, readiness scans,
  deadlines, and copyout; close plus exact fd reuse cannot retarget an active
  read, writev, send, receive, bind, listen, name, or option operation.
- `poll`, `ppoll`, `select`, and `pselect6` snapshot requested Files before
  subscribing or waiting. `F_DUPFD` and `F_DUPFD_CLOEXEC` install the caller's
  already-pinned File, with descriptor CLOEXEC state published atomically.
- INET, accepted INET, UNIX, accepted UNIX, NETLINK, and VSOCK release schedules
  use real Files and FdTables across duplicate, fork, failed publication, table
  drop, active pin, close, and exact descriptor reuse.
- SCM_RIGHTS receive publication is socket-owned around an explicit FdTable,
  limit, CLOEXEC policy, file batch, and copyout callback. EMFILE and copy faults
  preserve the installed prefix, roll back the current reservation, discard the
  suffix, and report truncation; MSG_PEEK installs duplicates while retaining
  queued rights.
- AF_UNIX stream, datagram, seqpacket, and unaccepted-child final release drops
  unread rights outside queue and socket locks, then runs canonical collection.
  Nested collection requests use one IDLE/RUNNING/PENDING state word with a
  validated pending RMW, preventing recursion and lost requests.
- Non-network namespaces use canonical concrete owners and weak live/nsfs
  indexes. Tasks and namespace fds retain exact identities, PID visibility maps
  retain weak ancestor owners, and task exit releases namespace membership
  before publishing `Zombie` even if pidfd retains the task allocation.
- IPC and UTS state is attached to exact owner finalizers. Mount state remains
  owned by VFS `MntNamespaceRef`; reservations, copy/snapshot, graft, procfs
  open state, and detached `open_tree` handles retain owners through commit or
  abort, and detached mounts rebind to the destination before publication.
- TIME namespaces provide native monotonic and boottime offsets across clone,
  clone3, unshare, setns, procfs `timens_offsets`, and POSIX clocks. Procfs
  writes authorize with opener credentials and resolve the target at write time.
- `listns` enumerates the canonical active namespace trees. Its snapshots hold
  lifetime pins, not active membership, so snapshot-first preserves copyout and
  final-drop-first cannot rediscover or reactivate a dead namespace.
- POSIX timers use native realtime, monotonic, boottime, TAI, process CPU, and
  thread CPU domains. Wall timers live in an ordered queue consumed by x86/ARM
  one-shot IRQ paths; process CPU accounting is O(1), periodic overruns retain
  one pending signal, and delete/exec/exit remove timer lifetime state.
- Active blocked network operations retain their original File, so descriptor
  close and reuse cannot cancel, redirect, or release the operation's endpoint.
  TCP/VSOCK connect and accept, TCP/UNIX sends, and NETLINK/VSOCK/UNIX receives
  arm waits under canonical state locks and publish terminal state before wake.
- AF_UNIX stream send queues provide bounded partial progress; datagram and
  seqpacket queues provide bounded atomic records. Dequeue, shutdown, and final
  release wake blocked writers, and datagram read shutdown advances one
  observable generation.
- The composed owner-retention Loom matrix covers materialized state, socket
  files, passed sockets, namespace fds, pidfd targets, listns snapshots, blocked
  I/O, and ingress leases. Operation-first and close-first schedules compose
  production registry and reaper transitions and prove no resurrection plus one
  exact harvest/claim winner.

## Verification

- B868 hosted: net 748/748, netlink 104/104, socket 31/31, syscalls 99/99;
  focused AF_UNIX 94/94 and TCP listener 12/12; zero failures. x86_64 and
  aarch64 kernel builds pass.

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
- B854 merge-gate snapshot: hosted socket 23, net 714, netlink 101,
  syscalls 87, fs 114, select ownership 3, VFS vectored I/O 16, write limits 4,
  mount-readonly 4, and fd-table duplication 3; x86 and ARM custom-target
  checks passed. VFS library is
  109/110 because `tests_d4b::t1b_idmap_chown_in` fails identically on untouched
  `main` (0/1 there). Independent send/NETLINK and VSOCK lifecycle reviews are
  clean after deterministic response-failure, reentry, tuple-reuse, and tail-handoff fixes.
- B855 hosted net 719, socket 31, syscalls 88, VFS SCM install 3, focused SCM
  receive 8, and SCM-GC 12 passed; x86 and ARM custom-target checks, length lint,
  diff check, and independent Linux/concurrency reviews passed. A separate
  pre-existing VSOCK test-isolation race was reproduced under parallel tests;
  sequential net remains 719/719.
- B856 removes the private VSOCK test mutex and routes all shared driver/table
  fixtures through the canonical poison-recovering lock. Three concurrent
  32-thread stress runs passed 92/92 VSOCK tests each. Full-net stress exposed
  separate forwarding-sysctl and AF_UNIX fixture races; B857 closes the former
  and N28.2 tracks the latter.
- B857 gives each forwarding fixture a retained private namespace and keys its
  sysctl, interfaces, routes, and addresses to that owner. Six 32-thread targeted
  schedules passed 3/3 each; full sequential net passed 719/719.
- `make x86` and `make arm` passed.
- B865 stable hosted gate: namespace identity 6, IPC 40, nscg 26, scheduler
  158, syscall library 88, hosted namespace syscall 10, procfs 48, devfs 15,
  pidfd 6, netlink 101, net 738, network namespace 3, and namespace Loom 6;
  zero failures. All 44 VFS integration targets touched by the owner-provider
  migration pass. Namespace identity, nscg, mount ownership, and detached-tree
  ownership each passed 100-run stress gates. Full VFS library remains 112/113
  with `tests_d4b::t1b_idmap_chown_in` failing identically on main.
- B865 x86_64 and aarch64 kernel builds pass from the stable commit set.
- B865 x86 smoke reached `basic.target` in 74s on the immediate rerun. The
  first attempt hit a transient systemd `dbus.socket` `EBADF` abort. ARM smoke
  is host-blocked before QEMU because vendored arm64-efi GRUB modules are absent;
  the aarch64 kernel build itself passes.
- B866 nscg 28/28 and syscall library 88/88 pass. Snapshot-first and
  final-drop-first controlled schedules pass 100/100 repetitions; x86_64 and
  aarch64 kernel builds pass.
- B867 namespace identity 10/10, nscg 37/37, procfs 58/58, scheduler 172/172,
  syscall library 98/98, timekeeper 3/3, and time-namespace 8/8 pass. Ordered
  timer queue/model tests include sub-10ms one-shot selection and no-growth IRQ
  restart. Workspace check and x86_64/aarch64 kernel builds pass.
- B867 post-main-integration x86 smoke reached `basic.target` in 102s. ARM
  rebuilt successfully, but smoke is host-blocked before QEMU because vendored
  `arm64-efi` GRUB modules are absent; redundant retries were stopped after the
  packaging failure was confirmed.
- B869 hosted net 752/752, focused Linux netdev 10/10, Virtio net 26/26,
  network namespace 4/4, and namespace Loom 8/8 pass. Workspace and default
  module checks, changed-file length/diff checks, host/x86/ARM KPI header smokes,
  and x86_64/aarch64 kernel builds pass. Full hosted modules is 183/184 because
  `linux_debugfs_automount::debugfs_automount_resolves_through_vfs_walk` fails
  identically on untouched main with `Enodev`. x86 smoke reached `basic.target`
  in 66s; ARM smoke stops before QEMU at the existing missing vendored
  `arm64-efi` GRUB-module host prerequisite.
- B870 hosted net 752/752 and network namespace 4/4 pass. Full Loom net 756/756
  and network namespace 9/9 pass, including all eight owner-retention boundaries
  composed with production lookup/final-drop/claim and reaper publication/
  harvest transitions. Workspace check and x86_64/aarch64 kernel builds pass.
- N03.7 smoke reached `basic.target`: x86 70s, ARM 129s.
- `git diff --check`, length lint, and changed-file code lint passed.

## Remaining network work

- N26.4 VSOCK socket-option coverage remains. B854 owns atomic connect,
  failed-connect `SO_ERROR`, typed bind, canonical poll notification, SIGPIPE,
  and blocked-wait shutdown linearization.
- N04-N24 and the completion gate in `scratch/network-plan.md`.
- Correct stale syscall matrix evidence/status while executing the owning lanes.

## First resume command

`cd /home/nd/oxide-wt/B871-network-common-socket-filter && git status --short --branch`
