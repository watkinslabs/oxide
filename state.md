# state - network completion

Update: 2026-07-16.

## Current lane

- B1103 converts `SIOCGIFCONF` to fault-recoverable header import, bounded
  kernel record assembly, variable payload copyout, and returned-length
  copyout. Remaining fixed-field output writes, compat layout, and direct
  differential coverage remain for N24.

- B1104 converts all remaining fixed-field `ifreq` input/output paths,
  including flags, ifindex, MTU, hardware address, TX queue length, and
  `SIOCGIFNAME`, to shared fault-recoverable uaccess. Compat layout and direct
  differential coverage remain for N24.

- B1105 replaces shared `write_i32_pair` and `write_user_i32` raw user-memory
  stores with fault-recoverable uaccess. This closes the socketpair fd-array
  copyout primitive; N16 remains partial pending direct syscall-context and
  differential coverage.

- B1106 moves socketpair argument validation ahead of current-task and fd-table
  work and makes AF_UNIX reject every nonzero protocol, matching Linux. N16
  remains partial pending direct syscall-context and differential coverage.

- B1108 makes common SOL_SOCKET integer setters require a valid four-byte
  optval for SO_KEEPALIVE, SO_SNDBUF, SO_RCVBUF, and SO_PASSCRED, preserving
  Linux EINVAL/EFAULT ordering instead of silently succeeding on bad input.

- B1109 converts SO_LINGER and SO_RCVTIMEO/SO_SNDTIMEO struct copyin to shared
  fault-recoverable uaccess with required-length EINVAL ordering and saturating
  nanosecond conversion. N17 remains partial for the broader option matrix.

- B1110 removes raw scalar and SO_BINDTODEVICE name reads from common
  setsockopt, using shared fault-recoverable uaccess for integer, short-scalar,
  and byte-string imports. N17 remains partial for family-specific paths and
  differential coverage.

- B1111 converts multicast IPv4/IPv6 scalar, sockaddr, membership, and source
  request imports to shared fault-recoverable uaccess. The multicast helper now
  has no raw volatile user reads; N17 remains partial for full Linux matrix and
  differential coverage.

- B1112 makes TCP_NODELAY use the required scalar copyin path, returning
  Linux-shaped EINVAL/EFAULT before changing the socket option. N17 remains
  partial for the broader TCP and option matrix.

- B1113 converts SO_PEERCRED copyout to bounded value-before-length uaccess,
  honoring requested optlen and returning EFAULT without raw user writes. N18
  remains partial for the broader getter matrix and differential coverage.

- B1114 converts multicast getsockopt scalar, sockaddr, and variable-filter
  imports/exports to shared fault-recoverable uaccess; no raw volatile user
  accesses remain in that helper. N18 remains partial for the broader getter
  matrix and differential coverage.

- B1115 converts SO_BINDTODEVICE getter length/name import and copyout to
  shared fault-recoverable uaccess, preserving value-before-length EFAULT
  ordering. N18 remains partial for the broader getter matrix.

- B1102 converts shared IPv4 sockaddr output for address, netmask, and
  broadcast interface getters to fault-recoverable `copy_to_user` and returns
  `EFAULT` on copyout failure. Variable-length `SIOCGIFCONF` and remaining
  fixed output fields remain for N24.

- B1101 replaces raw volatile `ifreq` imports with fault-recoverable shared
  uaccess copying and makes interface-name parsing consume that snapshot.
  Output copyout, compat layout, and direct syscall differential coverage
  remain for N24. Custom target verification is currently blocked by the
  pre-existing missing VDSO blob and unrelated AF_VSOCK constant errors.

- B1100 adds canonical Linux `tx_queue_len` ownership and wires
  `SIOCGIFTXQLEN`/`SIOCSIFTXQLEN` with negative-input validation. No shadow
  queue state is introduced. Broader uaccess/compat and differential coverage
  remain for N24.

- B1099 adds `NetDev::set_mac`, Linux `ndo_set_mac_address` delegation, and
  Ethernet validation for `SIOCSIFHWADDR`. No registry shadow address is
  written; unsupported devices report backend `EOPNOTSUPP`. TX-queue, broader
  uaccess/compat, and differential coverage remain for N24.

- B1098 adds `NetDev::set_mtu`, Linux-adapter `ndo_change_mtu` delegation, and
  bounded `SIOCSIFMTU` dispatch. No shadow MTU state is introduced; unsupported
  devices report backend `EOPNOTSUPP`. Hardware-address, tx-queue, broader
  uaccess/compat, and differential coverage remain for N24.

- B1097 adds namespace/family-scoped `Ioctl` admission before `SIOCGSKNS` and
  interface `SIOC*` dispatch. Existing `CAP_NET_ADMIN` mutation checks remain
  ordered after policy admission. Broader ioctl command, uaccess/compat, and
  differential coverage remain for N24.

- B1096 adds netlink `read_file` and `read_nonblock_file` ownership. Kernel
  blocking reads arm/recheck the existing wait list; nonblocking reads return
  `EAGAIN`; hosted receive tests pass. Integrated syscall-context ordering and
  wake/error differential remain for N27.

- B1095 routes netlink inode `read()` through the canonical queue-before-error
  state machine and verifies queued data, pending errno, and subsequent empty
  behavior. Blocking read wake/arm integration and full syscall-context
  ordering evidence remain for N27.

- B1094 adds hosted VSOCK option contract coverage for defaults, min/max
  validation, max clamping, and unknown options. Linux/glibc differential
  coverage remains open.

- B1093 exposes per-namespace/per-operation allow and deny counter snapshots
  and proves namespace/operation isolation, replacement reset, and removal
  cleanup in deterministic security tests. Integrated syscall-context policy
  differential and namespace teardown scenarios remain.

- B1092 centralizes namespace-scoped operation evaluation in an unconditional
  network admission module and applies `NameQuery` to netlink getsockname plus
  `Ioctl` to netlink queue-count ioctls. Modeled N19 call-site coverage is now
  complete; policy differential, namespace teardown, and counter evidence
  remain.

- B1091 adds the namespace-scoped `Ioctl` security verdict to the owning INET
  and VSOCK ioctl methods before queue state is read. Netlink ioctl, broader
  interface ioctl coverage, and policy differential/teardown evidence remain.

- B1075/B1077 implement N19's canonical network security boundary. The
  security crate now owns namespace/operation keyed hooks with real verdicts
  and counters; packet ingress/forwarding is wired, while local output and
  socket operation call sites remain open.
- B1077 wires the packet ingress/forwarding path through that boundary using
  the retained ingress namespace owner. Local output and socket operations
  remain open.
- B1076 advances N26.4: VSOCK now owns and validates the three Linux
  `SOL_VSOCK` buffer options. Transport enforcement and differential coverage
  remain open.
- B1078 applies the configured VSOCK receive size to the connection credit
  advertisement on connect and accept; differential coverage remains open.
- B1079 adds the namespace-scoped `Send` security verdict to the common local
  output path before netfilter traversal. Socket-operation hooks remain open.
- B1080 adds the namespace-scoped `Create` verdict to the common `socket(2)`
  admission path before family object and fd allocation.
- B1081 adds the namespace-scoped `Bind` verdict to the canonical socket work
  layer before family-specific bind mutation.
- B1082 adds the namespace-scoped `Connect` verdict before disconnect or
  family-specific peer/table mutation.
- B1083 adds the namespace-scoped `Listen` verdict before UNIX or TCP listener
  publication.
- B1084 adds the namespace-scoped `Accept` verdict before pending child
  consumption.
- B1085 adds the namespace-scoped `Send` verdict to the shared socket send
  dispatch before protocol transmission.
- B1086 adds the namespace-scoped `Receive` verdict to the shared receive work
  layer before queue consumption and blocking retry.
- B1087 adds the namespace-scoped `Shutdown` verdict before socket latches or
  protocol transport mutation.
- B1088 adds the canonical `Option` security boundary for setsockopt/getsockopt
  through the owning net helper.
- B1089 adds the canonical `SocketPair` admission before endpoint or fd
  publication.
- B1090 adds the canonical `NameQuery` admission before VSOCK/INET address
  snapshots; netlink name-query remains open.

- Active branch: `B1115-getsockopt-device-uaccess`, advancing N18 from current
  `origin/main` merge `d02e7224b`.
- N07 packet behavior is complete. The portable GNU/glibc AF_PACKET differential contains
  95 deterministic records covering the complete VNET/GSO matrix, direct epoll
  TX-ring states, V3 retire timeout, concurrent fanout-member close,
  split/unmap/fork and `mremap` mapping lifetime, and close while blocked receive.
- Linux and Oxide outputs match byte-for-byte on actual x86_64 and aarch64 boots.
  Full net passes 863/863. Both GNU targets compile with their native glibc
  interpreters.
- The blocked-receive probe pre-opens its sender before close. This excludes fd
  reuse and proved the earlier apparent mismatch was a harness race, not a
  kernel defect.
- ARM verification exposed three independent current-main compile regressions.
  B977 ESR exception-class width, B979 devpts permission width, and B980 procfs
  permission width are fixed in merged PRs #3274, #3276, and #3278.
- B886 found two descriptor/socket contract defects. `unshare(CLONE_FILES)` now
  publishes a private fd-table snapshot, with a hosted ownership regression.
  The D-Bus startup failure itself was a `getsockopt(SOL_SOCKET, *)` dispatch
  bug: missing unqualified Rust constants became catch-all pattern bindings.
  Canonical `net::uapi` constant patterns restore `SO_DOMAIN`, `SO_TYPE`,
  `SO_ACCEPTCONN`, `SO_PROTOCOL`, and every later option arm. A focused hosted
  regression passes; x86 reaches `basic.target` with no broker/launcher failure.
- ARM lockstep exposed and B886 fixes remote signal-target rescheduling, GICv3
  private-interrupt Group 1 routing, and per-CPU CNTV timer mode ownership.
  Final post-merge smoke reaches `basic.target` on ARM in 120s and x86 in 68s
  with no D-Bus broker or launcher failure.

## Active work

- The syscall shim now imports one receive destination, retains one File, and
  dispatches every family through the shared recvmsg receive core. Source
  lengths are accessed after payload delivery, including Linux consume-before-
  `EFAULT`/`EINVAL` behavior, and invalid payload ranges are rejected before fd
  resolution or waiting while in-range page faults remain protocol-owned.
- Duplicate per-family `recvfrom` dispatch and the standalone NETLINK/UNIX
  receive implementations are removed. Family-specific `MSG_OOB` rejection is
  explicit; UDP's Linux behavior continues to ignore `MSG_OOB`.
- Hosted syscalls pass 128/128, focused packet receive passes 102/102, both
  GNU/glibc targets compile, both kernel targets build, and the complete
  99-record x86 Linux/Oxide differential is byte-identical. Publication and
  merge remain before N08 is checked complete.

## Remaining network work

- N08 is complete in PR #3371. N09 is merged with sendmsg differential records.
  N10 is actively advanced on `B1067-network-recvmsg` with corrected ancillary
  copy-fault propagation. N11 is actively advanced on
  `B1068-network-recvmmsg` with corrected fd/timeout ordering. N12 is actively
  advanced on `B1069-network-shutdown` with dual-stack UDP receive shutdown
  correction. N13 is merged with bind sockaddr range validation. N15 is actively
  advanced on `B1071-network-socknames` with corrected sockaddr value-result
  copyout ordering. N14 is actively advanced on `B1072-network-listen` with
  bounded VSOCK backlog publication. N17 is actively advanced on
  `B1073-network-setsockopt` with corrected integer option fault/length errors.
  N18 is actively advanced on `B1074-network-getsockopt` with corrected generic
  option copyout ordering; N16, N20-N25, N26.4, N27,
  N19 is partial on B1093;
  and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

Resume `/home/nd/oxide-wt/B1065-network-recvfrom`, finish N08 differential and
dual-target evidence, update `syscall-compliance-matrix.md`, then push, open,
merge, and clean up the PR before claiming N09.
