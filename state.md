# state - network completion

Update: 2026-07-15.

## Current lane

- Active branch: `B873-network-packet-memberships`, created from current
  `origin/main` merge `ff04b77f3` after B872 merged in PR #3152.
- N06 owns Linux AF_PACKET memberships, promiscuous/all-multicast reference
  accounting, interface move/removal, namespace teardown, and close races.
- No competing N06 branch or worktree existed when B873 was claimed.

## N06 implementation

- Native `SOL_PACKET` add/drop membership import calls one socket-layer work
  function; socket-local duplicate counts and device-wide multicast,
  promiscuous, all-multicast, and unicast references serialize under RTNL.
- Effective packet mode and administrative interface intent share one device
  filter owner. Unrelated flag changes cannot retain temporary packet mode.
- Linux module drivers receive effective flags and stable multicast/unicast
  address lists through `ndo_set_rx_mode`.
- Final file release, interface unregister, namespace move, and concurrent
  admitted add/close detach exact interface generations and wake bound sockets
  with `ENETDOWN`.

## N06 verification

- Passed: net 770/770, syscalls 103/103, socket 33/33, Virtio net 27/27,
  Linux netdev 14/14, workspace check, host/x86_64/aarch64 KPI header smokes,
  x86_64/aarch64 kernel builds, diff checks, and touched-file caps.
- Full modules: 187/188; only the pre-existing debugfs automount fixture fails
  with `Enodev`, matching the documented main baseline.

## Recently merged

- N05 packet observation parity merged in PR #3152 at `ff04b77f3`.
- B872 gates: net 764/764, Linux netdev 13/13, Virtio net 27/27, socket 33/33,
  syscalls 99/99, workspace check, x86_64/aarch64 builds, diff and file caps.

## Remaining network work

- Merge B873, mark N06 complete with PR/merge evidence, then claim N07 from
  refreshed `origin/main`. N07-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B873-network-packet-memberships && git status --short --branch`
