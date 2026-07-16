# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B1065-network-recvfrom`, completing N08 and syscall row 45
  from current `origin/main` merge `8173be4f0`.
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
- Hosted receive-import tests and the x86_64 kernel target build pass. Direct
  glibc differential coverage, final matrix evidence, ARM build, and integrated
  verification remain before N08 can merge.

## Remaining network work

- N08 is active. N09-N25, N26.4, N27, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

Resume `/home/nd/oxide-wt/B1065-network-recvfrom`, finish N08 differential and
dual-target evidence, update `syscall-compliance-matrix.md`, then push, open,
merge, and clean up the PR before claiming N09.
