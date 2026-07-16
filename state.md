# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B965-network-packet-race-matrix`, based on current merged
  `origin/main` plus N07.10.9 implementation and evidence.
- N07.10.9 is complete. The portable GNU/glibc AF_PACKET differential contains
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
- N07.10.10 is the only remaining AF_PACKET campaign item. Two x86 campaign
  boots lose `dbus.socket` fds, hit systemd `safe_close()` EBADF, and freeze PID
  1 before login. The existing claimed lane is `B886-dbus-socket-fd-lifetime`.

## Remaining network work

- N07.10.10, N08-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B886-dbus-socket-fd-lifetime && git status --short --branch`
