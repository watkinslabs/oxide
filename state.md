# state - network completion

Update: 2026-07-15.

## Current lane

- Active branch: `B875-network-packet-option-abi`, created from current
  `origin/main` merge `fed783485` after the N07 audit merged in PR #3154.
- N07.1 owns shared packet-option UAPI/dispatch, packet-only checks,
  `PACKET_IGNORE_OUTGOING`, and unsupported-option evidence.
- No competing N07.1 branch, worktree, or implementation existed when B875
  was claimed.

## N07 audit result

- Only add/drop membership is implemented. All other active Linux packet
  options and all packet-level getsockopt paths currently return `ENOPROTOOPT`.
- Packet receive uses a fixed 64-frame queue with no packet statistics,
  fanout, auxdata/original-device metadata, or outgoing-ignore control.
- Packet-fd mmap has no dedicated backing and cannot provide TPACKET shared
  rings or mapped-ring lifetime. N07.1-N07.10 in `scratch/network-plan.md`
  now order the required work and prohibit inert option-only patches.

## Recently merged

- N06 packet memberships and device lifecycle merged in PR #3153 at
  `490c315b7`.
- B873 gates: net 770/770, syscalls 103/103, socket 33/33, Virtio net 27/27,
  Linux netdev 14/14, workspace check, KPI header smokes, and x86_64/aarch64
  builds. Full modules retained its unrelated debugfs baseline failure.

## Remaining network work

- Implement, verify, and merge N07.1, then claim N07.2 from refreshed main.
  N07.2-N07.10, N08-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B875-network-packet-option-abi && git status --short --branch`
