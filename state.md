# state - network completion

Update: 2026-07-15.

## Current lane

- Active branch: `B876-network-packet-metadata`, created from current
  `origin/main` merge `537554cd9` after B875 merged in PR #3155.
- N07.2 owns `PACKET_AUXDATA`, `PACKET_ORIGDEV`, original-device retention,
  packet metadata, and recvmsg ancillary copyout.
- No competing N07.2 branch, worktree, or implementation existed when B876
  was claimed.

## N07.2 implementation

- Packet sockets retain one enqueue-time receive record containing
  sockaddr_ll identity and native auxdata fields after filter truncation.
- `PACKET_ORIGDEV` selects retained original interface identity at enqueue;
  observed/original leases must share one exact network namespace.
- `PACKET_AUXDATA` emits Linux status, full/snapshot length, network offset,
  checksum, TCP GSO, and hardware or SOCK_DGRAM inline VLAN metadata.
- Virtio and Linux-module RX carry driver checksum/offload metadata through
  the canonical netdev boundary; Virtio runtime state now has a focused child
  owner instead of exceeding the 500-line file cap.

## N07.2 verification

- Passed: net 774/774, syscalls 107/107, Virtio net 28/28, focused Linux
  netdev 5/5, workspace check, x86_64 build, aarch64 build, diff/file caps.
- Full modules retains unrelated debugfs automount baseline failure: 178/179.
- Full lint reports 1,989 findings versus 1,990 on `main`; B876-added code is
  clean.

## Recently merged

- N07.1 packet option ABI and outgoing control merged in PR #3155 at
  `537554cd9`; net 771/771, syscalls 106/106, workspace check, and dual target
  builds passed.
- N07 audit/decomposition merged in PR #3154 at `fed783485`.
- N06 packet memberships merged in PR #3153 at `490c315b7`.

## Remaining network work

- Commit, push, and merge N07.2, then claim N07.3 from refreshed main.
  N07.3-N07.10, N08-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B876-network-packet-metadata && git status --short --branch`
