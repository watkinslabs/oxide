# state - network completion

Update: 2026-07-16.

## Current lane

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

- Active branch: `B1083-network-security-listen`, advancing N19 from current
  `origin/main` merge `fd13b7f8a`.
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
  N19 is partial on B1075;
  and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

Resume `/home/nd/oxide-wt/B1065-network-recvfrom`, finish N08 differential and
dual-target evidence, update `syscall-compliance-matrix.md`, then push, open,
merge, and clean up the PR before claiming N09.
