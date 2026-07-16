# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B886-dbus-socket-fd-lifetime`, completing N07.10.10 and the
  N07 integrated dual-architecture gate.
- N07 is complete. The portable GNU/glibc AF_PACKET differential contains
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
- B886 reproduced the intermittent D-Bus fd loss and identified its Linux
  contract violation: `unshare(CLONE_FILES)` returned success without detaching
  the caller's shared descriptor table, so systemd's helper could close PID 1
  socket-activation fds. The syscall now publishes a private fd-table snapshot;
  a hosted ownership test proves peer descriptors survive helper close.
- ARM lockstep exposed and B886 fixes remote signal-target rescheduling, GICv3
  private-interrupt Group 1 routing, and per-CPU CNTV timer mode ownership.
  Final integrated smoke reaches `basic.target` on ARM in 128s and x86 in 68s.

## Remaining network work

- N08-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

Start N08 `recvfrom` row 45 from updated `origin/main` in a fresh numbered
worktree after B886 merges.
