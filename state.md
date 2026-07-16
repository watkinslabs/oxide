# state - network completion

Update: 2026-07-15.

## Current lane

- Active branch: `B872-network-packet-observation`, created from current
  `origin/main` merge `22bbe738f` after B871 merged in PR #3151.
- N05 owns AF_PACKET ingress/egress observation parity across physical,
  Linux-module, loopback, locally generated, and outgoing paths.
- Required contract: correct `sll_pkttype`, L2/L3 packet views, namespace and
  device identity, socket-filter execution, and exactly one delivery.
- No competing N05 branch or worktree existed when B872 was claimed.

## Recently merged

- B871 N04 common socket-filter parity merged in PR #3151 at `22bbe738f`.
  One File-pinned target owns attach/detach/lock/readback for AF_UNIX,
  AF_NETLINK, and AF_VSOCK. Receive paths preserve family payload views,
  zero-drop, positive truncation, accepted-child inheritance, and canonical
  live VSOCK socket/connection filter ownership.
- B871 gates: hosted net 758/758, netlink 105/105, socket 33/33, syscalls
  99/99, workspace check, and x86_64/aarch64 kernel builds passed. x86 smoke
  reached `basic.target` in 60s on immediate retry. ARM smoke remained blocked
  before QEMU by missing vendored `arm64-efi` GRUB modules; aarch64 build passed.
- B870 N03 owner-retention Loom matrix merged in PR #3150 at `868998ed0`.
- N03 canonical network-namespace lifetime and all child rows are complete.

## B872 first audit

- Enumerate every AF_PACKET tap call and classify ingress/egress, packet view,
  namespace owner, device identity, and `sll_pkttype` source.
- Trace physical Virtio, Linux module, loopback, local L3 output, forwarded,
  and AF_PACKET-originated traffic through canonical delivery.
- Compare behavior with Linux `packet_rcv`/`packet_rcv_spkt`, `dev_queue_xmit`,
  `netif_receive_skb`, and loopback paths before changing ownership.
- Build deterministic hosted tests for each path and duplicate suppression
  before running broad hosted, target-build, and smoke gates.

## Remaining network work

- N05-N24 and the completion gate in `scratch/network-plan.md`.
- N26.4 VSOCK socket-option coverage remains tracked by the plan/matrix.
- Correct stale syscall-matrix evidence while executing each owning lane.

## First resume command

`cd /home/nd/oxide-wt/B872-network-packet-observation && git status --short --branch`
