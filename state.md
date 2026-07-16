# state - network completion

Update: 2026-07-15.

## Current lane

- Active branch: `B873-network-packet-memberships`, created from current
  `origin/main` merge `ff04b77f3` after B872 merged in PR #3152.
- N06 owns Linux AF_PACKET memberships, promiscuous/all-multicast reference
  accounting, interface move/removal, namespace teardown, and close races.
- No competing N06 branch or worktree existed when B873 was claimed.

## Recently merged

- N05 packet observation parity merged in PR #3152 at `ff04b77f3`.
- B872 gates: net 764/764, Linux netdev 13/13, Virtio net 27/27, socket 33/33,
  syscalls 99/99, workspace check, x86_64/aarch64 builds, diff and file caps.

## N06 first audit

- Trace `PACKET_ADD_MEMBERSHIP`/`PACKET_DROP_MEMBERSHIP`, membership ownership,
  device flags/reference counts, move/unregister, namespace teardown, and final
  socket release against Linux packet socket and netdevice lifecycle behavior.
- Build deterministic hosted race/lifecycle tests against canonical device and
  namespace generations before implementation.

## Remaining network work

- N06-N24, N26.4, and the completion gate in `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B873-network-packet-memberships && git status --short --branch`
